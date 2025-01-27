const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const saltRounds = 10; 
const crypto = require('crypto');
const excel = require('exceljs');

require('dotenv').config({
  path: path.join(__dirname, '.env') 
});


const app = express();
const port = process.env.DB_PORT;
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

connection.connect((error) => {
  if (error) {
    console.error('Error connecting to MySQL:', error);
  } else {
    console.log('Connected to MySQL database');
  }
});


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('images'));
app.use(session({
  secret: process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: true
}));
app.use(express.urlencoded({ extended: false }));
app.use('/images', express.static(path.join(__dirname, 'public', 'images')));
app.use(express.static('images'));
app.use(express.json());
const diskStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); 
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname); 
  }
});


const memoryStorage = multer.memoryStorage();
const uploadDisk = multer({ storage: diskStorage });
const uploadMemory = multer({ storage: memoryStorage });


const dynamicUpload = (req, res, next) => {
  const storageType = req.query.storage === 'disk' ? uploadDisk : uploadMemory;
  
  
  const fields = [];
  for (let i = 0; i < 10; i++) {
    fields.push({ name: `images${i}`, maxCount: 1 }); 
  }

  const dynamicUploader = storageType.fields(fields);
  dynamicUploader(req, res, next);
};

const generateSecretKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

console.log('Generated Secret Key:', generateSecretKey());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
res.render('FRONT');
});

app.get('/login', (req, res) => {
  res.render('login'); 
});

app.post('/userlogin', (req, res) => {
  const mobileNumber = req.body.mobilenumber;
  const password = req.body.password;

  if (!mobileNumber || !password) {
      return res.status(400).json({ error: 'Mobile number and password are required' });
  }

  const userTypeQuery = `
      SELECT 'user' as type FROM usersignin WHERE mobilenumber = ? AND access = 1
      UNION ALL
      SELECT 'store' as type FROM storesignin WHERE mobilenumber = ?
      UNION ALL
      SELECT 'admin' as type FROM admin WHERE mobileNumber = ?
  `;

  const userTypeParams = [mobileNumber, mobileNumber, mobileNumber];

  connection.query(userTypeQuery, userTypeParams, (error, results) => {
      if (error) {
          console.error('Error authenticating user:', error);
          return res.status(500).json({ error: 'Error in database connection' });
      }

      if (results.length === 0) {
          return res.status(400).json({ error: 'Invalid mobile number or password' });
      }

      const userType = results[0].type;

      if (userType === 'user') {
          const query = `SELECT idusersignin, pincode, password, name FROM usersignin WHERE mobilenumber = ?`;
          connection.query(query, [mobileNumber], (error, userResults) => {
              if (error) {
                  console.error('Error retrieving user:', error);
                  return res.status(500).json({ error: 'Error in database connection' });
              }

              if (userResults.length === 0) {
                  return res.status(400).json({ error: 'Invalid mobile number' });
              }

              const userPincode = userResults[0].pincode;
              const storedPassword = userResults[0].password;

              bcrypt.compare(password, storedPassword, (bcryptError, passwordMatch) => {
                  if (bcryptError) {
                      console.error('Error comparing passwords:', bcryptError);
                      return res.status(500).json({ error: 'Password mismatch' });
                  }

                  if (!passwordMatch) {
                      return res.status(400).json({ error: 'Invalid password' });
                  }

                  const userId = userResults[0].idusersignin;
                  req.session.userId = userId;

                  const userName = userResults[0].name;

                  const storeQuery = `SELECT storeid, name, storepincode FROM storesignin`;
                  connection.query(storeQuery, (error, storeResults) => {
                      if (error) {
                          console.error('Error retrieving store:', error);
                          return res.status(500).json({ error: 'Error in database connection' });
                      }

                      const matchingStores = storeResults.filter(store => {
                          if (store.storepincode) {
                              const storePincodes = store.storepincode.split(',');
                              return storePincodes.includes(userPincode.toString());
                          }
                          return false;
                      });

                      if (matchingStores.length > 0) {
                          const storeId = matchingStores[0].storeid;
                          const storeName = matchingStores[0].name;
                          req.session.storeId = storeId;

                          const tokenPayload = {
                              mobileNumber: mobileNumber,
                              userType: userType,
                              userId: userId.toString(),
                              storeId: storeId.toString()
                          };

                          const secretKey = generateSecretKey();
                          jwt.sign(tokenPayload, secretKey, (err, token) => {
                              if (err) {
                                  console.error('Error generating JWT token:', err);
                                  return res.status(500).send('Error generating token');
                              }

                              return res.status(200).json({
                                  token: token,
                                  secretKey: secretKey,
                                  redirectUrl: `/userstoredetails/${storeId}?userId=${userId}`
                              });
                          });
                      } else {
                          console.log('No matching stores found. Redirecting to /nostore with userId:', userId);
                          return res.status(200).json({
                              redirectUrl: `/nostore?userId=${userId}`
                          });
                      }
                  });
              });
          });
      } else if (userType === 'store') {
          const storeQuery = 'SELECT storeid, password FROM storesignin WHERE mobilenumber = ?';
          connection.query(storeQuery, [mobileNumber], (storeError, storeResults) => {
              if (storeError) {
                  console.error('Error retrieving store:', storeError);
                  return res.status(500).send('Error in database connection');
              }

              if (storeResults.length === 0) {
                  return res.status(400).send('Invalid mobile number');
              }

              const storedPassword = storeResults[0].password;

              if (password !== storedPassword) {
                  return res.status(400).json({ error: 'Invalid password' });
              }

              const storeId = storeResults[0].storeid;

              const tokenPayload = {
                  mobileNumber: mobileNumber,
                  userType: userType,
                  userId: storeId.toString(),
              };

              const secretKey = generateSecretKey();
              jwt.sign(tokenPayload, secretKey, (err, token) => {
                  if (err) {
                      console.error('Error generating JWT token:', err);
                      return res.status(500).send('Error generating token');
                  }

                  return res.status(200).json({
                      token: token,
                      secretKey: secretKey,
                      redirectUrl: `/storedetails/${storeId}`
                  });
              });
          });
      } else if (userType === 'admin') {
          const adminQuery = 'SELECT adminid, password, adminname, admincategory FROM admin WHERE mobileNumber = ?';
          connection.query(adminQuery, [mobileNumber], (adminError, adminResults) => {
              if (adminError) {
                  console.error('Error authenticating admin:', adminError);
                  return res.status(500).send('Error in database connection');
              }

              if (adminResults.length === 0) {
                  return res.status(401).send('Authentication failed');
              }

              const adminId = adminResults[0].adminid;
              const storedPassword = adminResults[0].password;
              const admincategory = adminResults[0].admincategory;

              bcrypt.compare(password, storedPassword, (bcryptError, passwordMatch) => {
                  if (bcryptError) {
                      console.error('Error comparing passwords:', bcryptError);
                      return res.status(500).send('Password mismatch');
                  }

                  if (!passwordMatch) {
                      return res.status(400).json({ error: 'Invalid password' });
                  }

                  const tokenPayload = {
                      mobileNumber: mobileNumber,
                      userType: userType,
                      userId: adminId.toString(),
                      admincategory: admincategory
                  };

                  const secretKey = generateSecretKey();
                  jwt.sign(tokenPayload, secretKey, (err, token) => {
                      if (err) {
                          console.error('Error generating JWT token:', err);
                          return res.status(500).send('Error generating token');
                      }

                      let redirectUrl;
                      if (admincategory === 'UserAdmin') {
                          redirectUrl = `/useradmin?adminid=${adminId}`;
                      } else if (admincategory === 'StockAdmin') {
                          redirectUrl = `/adminupdatestock?adminid=${adminId}`;
                      } else if (admincategory === 'SuperAdmin') {
                          redirectUrl = `/adminproductdetails?adminid=${adminId}`;
                      } else {
                          return res.status(400).json({ error: 'Invalid category' });
                      }

                      return res.status(200).json({
                          token: token,
                          secretKey: secretKey,
                          redirectUrl: redirectUrl
                      });
                  });
              });
          });
      } else {
          res.status(401).send('Authentication failed');
      }
  });
});



app.get('/nostore', (req, res) => {
  console.log('API called');
  const userId = req.query.userId;
  console.log('Received userId:', userId);

  if (!userId) {
    return res.status(400).send('Missing user ID');
  }

  const query = 'SELECT name FROM usersignin WHERE idusersignin = ?';
  connection.query(query, [userId], (error, results) => {
    if (error) {
      console.error('Error retrieving user:', error);
      return res.status(500).send('Internal Server Error');
    }

    if (results.length === 0) {
      console.log('User not found for userId:', userId);
      return res.status(400).send('User not found');
    }

    const userName = results[0].name;

    console.log('Retrieved userName:', userName);

    res.render('nostore', { userName: userName });
  });
});

// admin ..........................................................


app.get('/adminupdatestock', (req, res) => {
  const adminId = req.query.adminid;
  console.log("Received adminId:", adminId);

  if (!adminId) {
    console.error('Error: adminId is undefined or missing');
    return res.status(400).send('Bad Request: adminId is undefined or missing');
  }

  const storeQuery = 'SELECT adminid, adminname, admincategory FROM admin WHERE adminid = ?';

  connection.query(storeQuery, [adminId], (error, storeResults) => {
    if (error) {
      console.error('Error fetching store:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (storeResults.length > 0) {
      const name = storeResults[0].adminname;
      const admincategory = storeResults[0].admincategory;
      res.render('adminupdatestock', { hideDropdownItems: true, adminId: adminId, adminName: name, admincategory: admincategory }); 
    } else {
      console.error('Store not found');
      res.status(404).send('Store not found');
    }
  });
});

app.get('/update-adminstock', (req, res) => {
  const adminId = req.query.adminId;
  console.log("Received adminId:", adminId);

  if (!adminId) {
    console.error('Error: adminId is undefined or missing');
    return res.status(400).send('Bad Request: adminId is undefined or missing');
  }

  const storeQuery = 'SELECT adminid, adminname FROM admin WHERE adminid = ?';

  connection.query(storeQuery, [adminId], (error, storeResults) => {
    if (error) {
      console.error('Error fetching store:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (storeResults.length > 0) {
      const name = storeResults[0].adminname;
      res.render('update-adminStock', { hideDropdownItems: false, adminId: adminId, adminName: name });
    } else {
      console.error('Store not found');
      res.status(404).send('Store not found');
    }
  });
});

app.post('/update-adminstock/upload', uploadMemory.single('excelFile'), (req, res) => {
  console.log('File:', req.file); 

  if (!req.file) {
    console.error('Error: No file uploaded');
    return res.status(400).json({ message: 'No file uploaded' });
  }

  
  const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
  const worksheet = workbook.Sheets[workbook.SheetNames[0]];
  const data = xlsx.utils.sheet_to_json(worksheet);

  const adminId = req.body.adminId;

  if (!adminId) {
    console.error('Error: adminId is undefined or missing');
    return res.status(400).json({ message: 'Admin ID is missing' });
  }

  data.forEach(row => {
    const { 'Product ID': productid, Qty: newQty } = row;
    console.log("Processing row:", row);

    const query = 'UPDATE products SET qty = qty + ? WHERE productid = ?';
    connection.query(query, [newQty, productid], (error, results) => {
      if (error) {
        console.error('Error updating product quantity:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
      }
    });
  });

  res.json({ message: `Products quantity updated successfully` });
});

app.get('/download-allproducts-excel', (req, res) => {
  const adminId = req.query.adminId;

  if (!adminId) {
    console.error('Error: adminId is undefined or missing');
    return res.status(400).send('Bad Request: adminId is undefined or missing');
  }

  const query = `
  SELECT p.productid, p.productname, p.category, p.code, p.hsn, p.salesprice, p.weight, 0 AS qty, p.GST 
  FROM products p 
  WHERE p.producttype IN ('product', 'member');`;

  connection.query(query, [adminId], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      return res.status(500).send('Internal Server Error');
    }

    const workbook = new excel.Workbook();
    const worksheet = workbook.addWorksheet('Products');

    worksheet.columns = [
      { header: 'Product ID', key: 'productid', width: 15 },
      { header: 'Product Name', key: 'productname', width: 30 },
      { header: 'Category', key: 'category', width: 20 },
      { header: 'Code', key: 'code', width: 20 },
      { header: 'HSN', key: 'hsn', width: 15 },
      { header: 'Sales Price', key: 'salesprice', width: 15 },
      { header: 'Weight', key: 'weight', width: 15 },
      { header: 'Qty', key: 'qty', width: 10 },
      { header: 'GST', key: 'GST', width: 20 }
    ];

    results.forEach(product => {
      worksheet.addRow(product);
    });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=products.xlsx');

    workbook.xlsx.write(res)
      .then(() => {
        res.end();
      })
      .catch(err => {
        console.error('Error writing Excel file:', err);
        res.status(500).send('Internal Server Error');
      });
  });
});

app.get('/get-products', (req, res) => {
  const adminId = req.query.adminId;

  if (!adminId) {
    console.error('Error: adminId is undefined or missing');
    return res.status(400).send('Bad Request: adminId is undefined or missing');
  }

  const query = `
  SELECT productid, productname, category, code, hsn, salesprice, weight, qty 
  FROM products 
  WHERE producttype IN ('product', 'member');`;

  connection.query(query, [adminId], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      return res.status(500).send('Internal Server Error');
    }

    res.json(results);
  });
});


app.get('/adminstoredetails', (req, res) => {
  const adminId = req.query.adminid;
  if (!adminId) {
    res.status(400).send('Invalid adminid');
    return;
  }
  req.session.adminId = adminId; 

  const page = req.query.page || 1;
  const pageSize = 10;
  const offset = (page - 1) * pageSize;

  const storeQuery = `
    SELECT *
    FROM storesignin
    ORDER BY name
    LIMIT ? OFFSET ?;
  `;

  connection.query(storeQuery, [pageSize, offset], (error, results) => {
    if (error) {
      console.error('Error fetching store details: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    connection.query('SELECT COUNT(*) as storeCount FROM storesignin', (error, countResult) => {
      if (error) {
        console.error('Error fetching store count: ' + error);
        res.status(500).send('Internal Server Error');
        return;
      }

      const totalStoresCount = countResult[0].storeCount;
      const totalPages = Math.ceil(totalStoresCount / pageSize);

      const adminNameQuery = 'SELECT adminname, admincategory FROM admin WHERE adminid = ?';
      connection.query(adminNameQuery, [adminId], (adminError, adminResult) => {
        if (adminError) {
          console.error('Error fetching admin details: ' + adminError);
          res.status(500).send('Internal Server Error');
          return;
        }

        res.render('adminstoredetails', {
          hideDropdownItems: false,
          storeDetails: results,
          storeCount: totalStoresCount,
          adminName: adminResult[0] ? adminResult[0].adminname : 'Admin Name not found',
          admincategory: adminResult[0] ? adminResult[0].admincategory : 'Category not found',
          adminId: adminId,
          totalPages: totalPages,
          currentPage: page,
          pageSize: pageSize,
        });
      });
    });
  });
});


app.get('/addpincode/:storeid', (req, res) => {
  const storeId = req.params.storeid; 
  const adminId = req.query.adminId; 

  connection.query('SELECT adminname FROM admin WHERE adminId = ?', [adminId], (error, results) => {
    if (error) {
      console.error('Error fetching admin name:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (results.length > 0) {
      const adminName = results[0].adminname;

      connection.query('SELECT storepincode FROM storesignin WHERE storeid = ?', [storeId], (storeError, storeResults) => {
        if (storeError) {
          console.error('Error fetching storepincode values:', storeError);
          res.status(500).send('Internal Server Error');
          return;
        }

        const storePincodes = storeResults.map(result => result.storepincode);

        res.render('addpincode', { adminName, storeId, adminId, storePincodes });
      });
    } else {
      console.log('Admin ID not found');
      res.status(404).send('Admin ID not found');
    }
  });
});


app.post('/addpincode', (req, res) => {
  const { storeid, newStorePincode } = req.body;

 connection.query('SELECT storepincode FROM storesignin WHERE storepincode = ?', [newStorePincode], (checkErr, checkResults) => {
    if (checkErr) {
        console.error('Error checking existing pincode:', checkErr);
        return res.status(500).send('Internal Server Error');
    } else {
      if (checkResults.length > 0) {
        console.log('Store pincode already exists');
        res.status(400).send('Store pincode already exists');
      } else {
        connection.query('SELECT storepincode FROM storesignin WHERE storeid = ?', [storeid], (retrieveErr, retrieveResults) => {
          if (retrieveErr) {
            console.error('Error retrieving existing pincode values:', retrieveErr);
            res.status(500).send('Internal Server Error');
          } else {
            const existingStorePincodes = retrieveResults.map(result => result.storepincode);

            const updatedStorePincodes = existingStorePincodes.concat(newStorePincode);

            const updatedStorePincodeString = updatedStorePincodes.join(',');

            connection.query('UPDATE storesignin SET storepincode = ? WHERE storeid = ?', [updatedStorePincodeString, storeid], (updateErr, updateResults) => {
              if (updateErr) {
                console.error('Error updating pincode values:', updateErr);
                res.status(500).send('Internal Server Error');
              } else {
                console.log('Pincode value added successfully');
                res.status(200).send('Pincode added successfully');
              }
            });
          }
        });
      }
    }
  });
});


app.get('/adminorders', (req, res) => {
  const adminId = req.query.adminid;
  const selectedStore = req.query.storename;
  const storeNamesQuery = 'SELECT storeid, name FROM storesignin';

  connection.query(storeNamesQuery, (storeError, storeResults) => {
      if (storeError) {
          console.error('Error fetching store names: ' + storeError);
          res.status(500).send('Internal Server Error');
          return;
      }

      let orderQuery = `
 SELECT 
    o.orderid, 
    DATE_FORMAT(MAX(o.orderdate), '%d-%m-%Y %H:%i') AS formattedOrderDate,  -- Updated format
    MAX(o.storeid) AS storeid, 
    MAX(s.name) AS storename,  
    MAX(s.place) AS place,      
    MAX(o.userid) AS userid, 
    SUM(o.totalprice) AS totalprice, 
    MAX(o.status) AS status
FROM \`order\` o
LEFT JOIN storesignin s ON o.storeid = s.storeid
LEFT JOIN usersignin u ON o.userid = u.idusersignin
WHERE o.orderdate >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)

      `;

      const sqlParams = [];

      if (selectedStore) {
          orderQuery += ` AND s.name = ?`;
          sqlParams.push(selectedStore);
      }

      orderQuery += ` GROUP BY o.orderid`;
      orderQuery += ` ORDER BY MAX(o.orderdate) DESC`;

      connection.query(orderQuery, sqlParams, (error, results) => {
          if (error) {
              console.error('Error fetching order details: ' + error);
              res.status(500).send('Internal Server Error');
              return;
          }

          const adminNameQuery = 'SELECT adminname, admincategory FROM admin WHERE adminid = ?';
          connection.query(adminNameQuery, [adminId], (adminError, adminResults) => {
              if (adminError) {
                  console.error('Error fetching admin name: ' + adminError);
                  res.status(500).send('Internal Server Error');
                  return;
              }

              const adminName = adminResults[0] ? adminResults[0].adminname : '';
              const admincategory = adminResults[0] ? adminResults[0].admincategory : '';

              res.render('adminorders', {
                  hideDropdownItems: false,
                  orders: results,
                  adminId: adminId,
                  adminName: adminName,
                  admincategory: admincategory,
                  storeNames: storeResults,
                  selectedStore: selectedStore 
              });
          });
      });
  });
});


app.get('/order-details/:orderid', (req, res) => {
  const orderId = req.params.orderid;  
  const storeId = req.query.storeid;  
  const adminId = req.session.adminId;

  const orderDetailsQuery = `
    SELECT o.*,
     u.name AS username, 
     u.address, 
     s.name AS storename,
     DATE_FORMAT(o.orderdate, '%d-%m-%Y %H:%i') AS formattedOrderDate
    FROM \`order\` o
    LEFT JOIN usersignin u ON o.userid = u.idusersignin
    LEFT JOIN storesignin s ON o.storeid = s.storeid
    WHERE o.orderid = ? AND o.storeid = ?;
  `;


  const adminNameQuery = `
    SELECT adminname, admincategory
    FROM admin
    WHERE adminid = ?;
  `;

  connection.query(orderDetailsQuery, [orderId, storeId], (error, orderDetails) => {
    if (error) {
      console.error('Error fetching order details: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    connection.query(adminNameQuery, [adminId], (adminError, adminResult) => {
      if (adminError) {
        console.error('Error fetching admin name: ' + adminError);
        res.status(500).send('Internal Server Error');
        return;
      }

      const adminName = adminResult.length > 0 ? adminResult[0].adminname : '';
      const admincategory = adminResult.length > 0 ? adminResult[0].admincategory : '';


      res.render('orderdetails', { hideDropdownItems: false, orderDetails, adminName , adminId, admincategory });
    });
  });
});


app.get('/admineditstore/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  const adminId = req.query.adminid;

  connection.query('SELECT * FROM storesignin WHERE storeId = ?', [storeId], (error, results) => {
    if (error) {
      console.error('Error fetching store details: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (results.length === 0) {
      res.status(404).send('Store not found');
      return;
    }

    const store = results[0];

    connection.query('SELECT adminName, admincategory FROM admin WHERE adminId = ?', [adminId], (adminError, adminResults) => {
      if (adminError) {
        console.error('Error fetching admin details: ' + adminError);
        res.status(500).send('Internal Server Error');
        return;
      }
    
      if (adminResults.length === 0) {
        res.status(404).send('Admin not found');
        return;
      }
    
      const adminName = adminResults[0].adminName;
      const admincategory = adminResults[0].admincategory; 
    
      res.render('admineditstore', { hideDropdownItems: false, store, adminId, adminName, admincategory });
    });    
  });
});


app.post('/admineditstore/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  const { name, contactname, place, gstnumber, mobilenumber, storepincode, password, adminId } = req.body;

  connection.query('SELECT GROUP_CONCAT(storepincode) AS allPincodes FROM storesignin WHERE storeid != ?', [storeId], (error, results) => {
    if (error) {
      console.error('Error fetching pincodes: ' + error);
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }

    let allPincodes = [];
    if (results.length > 0 && results[0].allPincodes) {
      allPincodes = results[0].allPincodes.split(',').map(pin => pin.trim());
    }

    const enteredPincodes = storepincode ? storepincode.split(',').map(pin => pin.trim()) : [];
    const duplicatePincodes = enteredPincodes.filter(pin => allPincodes.includes(pin));

    if (duplicatePincodes.length > 0) {
      res.status(400).json({ duplicates: duplicatePincodes });
    } else {
      
      const updatedPincode = storepincode || store.storepincode;

      const updateQuery = 'UPDATE storesignin SET name = ?, contactname = ?, place = ?, gstnumber = ?, mobilenumber = ?, storepincode = ?, password = ? WHERE storeId = ?';
      connection.query(updateQuery, [name, contactname, place, gstnumber, mobilenumber, updatedPincode, password, storeId], (error, results) => {
        if (error) {
          console.error('Error updating store details: ' + error);
          res.status(500).json({ error: 'Internal Server Error' });
          return;
        }

        res.json({ success: true });
      });
    }
  });
});

app.delete('/admindeletestore/:storeid', (req, res) => {
  const storeId = req.params.storeid;

  connection.query('DELETE FROM storesignin WHERE storeId = ?', [storeId], (error, results) => {
    if (error) {
      console.error('Error deleting store: ' + error);
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }

    if (results.affectedRows === 0) {
      res.status(404).json({ error: 'Store not found' });
      return;
    }

    res.json({ success: true });
  });
});

app.get('/admineditsuccess', (req, res) => {
  res.render('admineditsuccess');
});


app.get('/storesignup', (req, res) => {
  const adminId = req.query.adminid;

  console.log('Received adminId:', adminId);

  if (!adminId) {
      res.status(400).send('Invalid adminid');
      return;
  }

  connection.query('SELECT adminname, admincategory FROM admin WHERE adminid = ?', [adminId], (error, adminResult) => {
      if (error) {
          console.error('Error fetching admin details:', error);
          res.status(500).send('Internal Server Error');
          return;
      }

      if (adminResult.length === 0) {
          res.status(404).send('Admin not found');
          return;
      }

      const adminName = adminResult[0].adminname;
      const admincategory = adminResult[0].admincategory;

      res.render('storesignup', { 
          adminId, 
          adminName, 
          admincategory 
      });
  });
});


app.post('/storeregister', (req, res) => {
  const { name, contactname, place, gstnumber, mobilenumber, storepincode, password, adminId } = req.body;

  if (!adminId) {
    res.status(400).send('Invalid adminid');
    return;
  }

  const mobileNumberQuery = 'SELECT mobilenumber FROM storesignin WHERE mobilenumber = ? ' +
                           'UNION SELECT mobilenumber FROM usersignin WHERE mobilenumber = ? ' +
                           'UNION SELECT mobilenumber FROM admin WHERE mobilenumber = ?';

  const queryParams = [mobilenumber, mobilenumber, mobilenumber];

  connection.query(mobileNumberQuery, queryParams, (err, results) => {
    if (err) {
      console.error('Error querying the database for mobile number: ', err);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (results.length > 0) {
      res.render('storemobilenumbererror', { adminId });
      return;
    }

    const pincodeQuery = 'SELECT * FROM storesignin WHERE storepincode = ?';
connection.query(pincodeQuery, [storepincode], (err, pincodeResults) => {
  if (err) {
    console.error('Error querying the database for pincode: ', err);
    res.status(500).send('Internal Server Error');
    return;
  }
      if (pincodeResults.length > 0) {
        res.render('storepincodeerror', { adminId });
        return;
      }


      const insertQuery = 'INSERT INTO storesignin (name, contactname, place, gstnumber, mobilenumber, storepincode, password) VALUES (?, ?, ?, ?, ?, ?, ?)';
      connection.query(insertQuery, [name, contactname, place, gstnumber, mobilenumber, storepincode, password], (err, result) => {
        if (err) {
          console.error('Error inserting data into the database: ', err);
          res.status(500).send('Internal Server Error');
          return;
        }

        res.render('adminstoreregistersuccess', { adminId });
      });
    });
  });
});


app.get('/createcategory', (req, res) => {
  const adminId = req.session.adminId;
  console.log('adminId for create:', adminId);

  if (!adminId) {
    console.error('Admin ID not found in session');
    res.status(401).send('Unauthorized');
    return;
  }

  connection.query('SELECT * FROM category', (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
      return;
    }

    const adminNameQuery = 'SELECT adminname, admincategory FROM admin WHERE adminid = ?';
    connection.query(adminNameQuery, [adminId], (adminError, adminResult) => {
      if (adminError) {
        console.error('Error fetching admin name and category: ' + adminError);
        res.status(500).send('Internal Server Error');
        return;
      }

      if (!adminResult || adminResult.length === 0) {
        console.error('Admin not found for adminId: ' + adminId);
        res.status(404).send('Admin not found');
        return;
      }

      const adminName = adminResult[0].adminname;
      const admincategory = adminResult[0].admincategory;

      res.render('createcategory', { 
        hideDropdownItems: false, 
        categories: results, 
        adminId, 
        adminName, 
        admincategory 
      });
    });
  });
});


app.get('/newcategory', (req, res) => {
  const adminId = req.session.adminId;

  if (!adminId) {
    console.error('Admin ID not found in session');
    res.status(401).send('Unauthorized');
    return;
  }

  const adminNameQuery = 'SELECT adminname, admincategory FROM admin WHERE adminid = ?';
  connection.query(adminNameQuery, [adminId], (adminError, adminResult) => {
    if (adminError) {
      console.error('Error fetching admin name: ' + adminError);
      res.status(500).send('Internal Server Error');
      return;
    }
  
    if (!adminResult || adminResult.length === 0) {
      console.error('Admin not found for adminId: ' + adminId);
      res.status(404).send('Admin not found');
      return;
    }
  
   const adminName = adminResult[0].adminname;
   const admincategory = adminResult[0].admincategory;
  
    res.render('newcategory', { hideDropdownItems: false, adminId, adminName, admincategory }); 
  });
});


app.post('/newcategory', uploadMemory.single('imagePath'), (req, res) => {
  const { name } = req.body;
  const imageFile = req.file;

  if (!imageFile) {
    return res.status(400).json({ success: false, message: 'No image uploaded' });
  }

  try {
    
    const base64Image = imageFile.buffer.toString('base64');

    
    const query = 'INSERT INTO category (name, imagepath) VALUES (?, ?)';
    connection.query(query, [name, base64Image], (err, result) => {
      if (err) {
        console.error("Error creating category:", err);
        res.status(500).json({ success: false, message: 'Failed to create category' });
        return;
      }

      console.log("New category created:", result.insertId);
      res.status(200).json({ success: true, message: 'Category created successfully' });
    });
  } catch (error) {
    console.error("Error processing uploaded file:", error);
    res.status(500).json({ success: false, message: 'Failed to process uploaded image' });
  }
});

app.get('/downloadexceltemplate', (req, res) => {
  const headers = [
    { header: 'producttype', key: 'producttype', width: 20 },
    { header: 'parentid', key: 'parentid', width: 15 },
    { header: 'productname', key: 'productname', width: 30 },
    { header: 'category', key: 'category', width: 20 },
    { header: 'code', key: 'code', width: 20 },
    { header: 'hsn', key: 'hsn', width: 15 },
    { header: 'salesprice', key: 'salesprice', width: 15 },
    { header: 'weight', key: 'weight', width: 15 },
    { header: 'qty', key: 'qty', width: 10 },
    { header: 'GST', key: 'GST', width: 20 },
    { header: 'description', key: 'description', width: 50 },
    { header: 'imagepath', key: 'imagepath', width: 30 }
  ];

  const workbook = new excel.Workbook();
  const worksheet = workbook.addWorksheet('Products');

  worksheet.columns = headers;
  worksheet.getRow(1).font = { bold: true };

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename=products_template.xlsx');

  workbook.xlsx.write(res)
    .then(() => {
      res.end();
    })
    .catch(err => {
      console.error('Error writing Excel file:', err);
      res.status(500).send('Internal Server Error');
    });
});


app.post('/uploadexcel1', uploadMemory.single('file'), (req, res) => {
  const file = req.file;
  if (!file) {
    return res.status(400).send('No file uploaded.');
  }

  try {
    const workbook = xlsx.read(file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const data = xlsx.utils.sheet_to_json(sheet);

    let insertErrors = [];

    data.forEach((row, index) => {
      const {
        producttype,
        parentid,
        productname,
        category,
        code,
        hsn,
        salesprice,
        weight,
        qty,
        GST,
        description,
        imagepath
      } = row;

      let formattedGST;

      if (typeof GST === 'number') {
        if (GST <= 1) {
          formattedGST = `${GST * 100}%`;  
        } else {
          formattedGST = `${GST}`; 
        }
      } else if (typeof GST === 'string') {
        formattedGST = GST;
      } else {
        formattedGST = null;
      }

      let productQuery;
      let productValues;

      if (producttype === 'productfamily') {
        productQuery = 'INSERT INTO products (productname, producttype, parentid) VALUES (?, ?, 0)';
        productValues = [productname || null, producttype];
      } else {
        productQuery = 'INSERT INTO products (producttype, parentid, productname, category, code, hsn, salesprice, weight, qty, GST, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
        productValues = [
          producttype || null,
          parentid || null,
          productname || null,
          category || null,
          code || null,
          hsn || null,
          salesprice || null,
          weight || null,
          qty || null,
          formattedGST,  
          description || null
        ];
      }

      connection.query(productQuery, productValues, (err, result) => {
        if (err) {
          console.error(`Error inserting into products table at row ${index + 1}:`, err);
          insertErrors.push(`Error inserting into products table at row ${index + 1}: ${err.message}`);
          return;
        }

        if (producttype !== 'productfamily') {
          const productId = result.insertId;
          const imageQuery = 'INSERT INTO productimages (productid, imagepath, image_order) VALUES (?, ?, 1)';
          connection.query(imageQuery, [productId, imagepath || null], (err) => {
            if (err) {
              console.error(`Error inserting into productimages table at row ${index + 1}:`, err);
              insertErrors.push(`Error inserting into productimages table at row ${index + 1}: ${err.message}`);
            }
          });
        }
      });
    });

    if (insertErrors.length > 0) {
      return res.status(500).json({ message: 'Errors occurred while processing the file', errors: insertErrors });
    }

    res.send('Excel file uploaded and processed successfully.');
  } catch (error) {
    console.error('Error reading Excel file:', error);
    return res.status(500).json({ message: 'Error processing the file' });
  }
});


app.get('/createproduct', async (req, res) => {
  const adminId = req.session.adminId;

  connection.query('SELECT adminname, admincategory FROM admin WHERE adminId = ?', [adminId], (error, results) => {
    if (error) {
      console.error('Error fetching admin name:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (results.length > 0) {
      const adminName = results[0].adminname;
      const admincategory = results[0].admincategory;
      const categoryName = req.query.category;
      res.render('createproduct', { hideDropdownItems: false, adminId, adminName, categoryName, admincategory });
    } else {
      console.log('Admin ID not found');
      res.status(404).send('Admin ID not found');
    }
  });
});


app.post('/createproduct', dynamicUpload, (req, res) => {
  const { productname, producttype, category, code, hsn, salesprice, gst, weight, qty, description, adminid } = req.body;

  console.log('Received adminId:', adminid);
  console.log('Received files:', req.files);
  console.log('Received product details:', {
    productname, producttype,
    category,
    code,
    hsn,
    salesprice,
    gst,
    weight,
    qty,
    description
  });

  const productQuery = 'INSERT INTO products (productname, producttype, category, code, hsn, salesprice, gst, weight, qty, description, parentid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
  const productValues = [
    productname,
    producttype,
    category,
    code,
    hsn,
    salesprice[0],
    gst,
    weight[0],
    qty[0],
    description,
    -1
  ];

  connection.query(productQuery, productValues, (err, productResult) => {
    if (err) {
      console.error('Error adding product to the database:', err);
      res.status(500).json({ error: err.message });
      return;
    }

    const images = req.files;
    console.log('Images received:', images);

    if (Object.keys(images).length === 0) {
      res.status(400).json({ error: 'No images uploaded' });
      return;
    }

    connection.query('SELECT MAX(image_order) AS maxImageOrder FROM productimages WHERE productid = ?', [productResult.insertId], (err, rows) => {
      if (err) {
        console.error('Error getting max image_order:', err);
        res.status(500).json({ error: err.message });
        return;
      }

      const maxImageOrder = rows[0].maxImageOrder || 0;

      const imageValues = Object.keys(images).flatMap((key, index) => 
        images[key].map((image, imgIndex) => {
          const base64Image = image.buffer.toString('base64');
          console.log('Base64 encoded imagepath:', base64Image);
          return [
            productResult.insertId,
            base64Image,
            maxImageOrder + index + imgIndex + 1
          ];
        })
      );

      const addImagesQuery = 'INSERT INTO productimages (productid, imagepath, image_order) VALUES ?';

      connection.query(addImagesQuery, [imageValues], (err) => {
        if (err) {
          console.error('Error adding images to the database:', err);
          res.status(500).json({ error: err.message });
        } else {
          console.log('Redirecting to adminproductdetails. AdminId:', adminid);
          res.redirect('/createcategory');
        }
      });
    });
  });
});



app.post('/addfamily', dynamicUpload, (req, res) => {
  console.log('API /addfamily called');
  console.log('Request body:', req.body);
  console.log('Request files:', req.files);

  const { productname, category, code, hsn, gst, weight, salesprice, qty, description } = req.body;
  const adminid = req.body.adminid;

  console.log('Received adminId:', adminid);

  const verifyQuery = 'SELECT * FROM products WHERE productname = ? AND producttype = "productfamily"';
  connection.query(verifyQuery, [productname], (err, results) => {
    if (err) {
      console.error('Error verifying product name in the database:', err);
      res.status(500).json({ error: err.message });
      return;
    }

    if (results.length > 0) {
      res.status(400).json({ error: 'Product family with the same name already exists' });
    } else {
      const producttype = 'productfamily';

      const familyQuery = 'INSERT INTO products (productname, producttype, parentid) VALUES (?, ?, 0)';
      const familyValues = [productname, producttype];

      connection.query(familyQuery, familyValues, (err, familyResult) => {
        if (err) {
          console.error('Error adding product family to the database:', err);
          res.status(500).json({ error: err.message });
          return;
        }

        const parentid = familyResult.insertId;
        console.log('Product family added with ID:', parentid);

        const memberQuery = 'INSERT INTO products (parentid, productname, producttype, category, code, hsn, weight, salesprice, qty, gst, description) VALUES ?';
        const memberValues = [];

        if (Array.isArray(weight) && Array.isArray(salesprice) && Array.isArray(qty) && Array.isArray(code) && Array.isArray(hsn)) {
          for (let i = 0; i < weight.length; i++) {
            memberValues.push([parentid, productname, 'member', category, code[i], hsn[i], weight[i], salesprice[i], qty[i], gst, description]);
          }
        } else {
          memberValues.push([parentid, productname, 'member', category, code, hsn, weight, salesprice, qty, gst, description]);
        }

        connection.query(memberQuery, [memberValues], (err, result) => {
          if (err) {
            console.error('Error adding product family members to the database:', err);
            res.status(500).json({ error: err.message });
            return;
          }

          const memberIds = [];
          for (let i = 0; i < result.affectedRows; i++) {
            memberIds.push(result.insertId + i);
          }

          console.log('Product family members added with IDs:', memberIds);

          const images = req.files;
          if (!images || Object.keys(images).length === 0) {
            res.status(400).json({ error: 'No images uploaded' });
            return;
          }

          const imageValues = Object.keys(images).flatMap((key, index) => {
            return images[key].map((image, imgIndex) => {
              const base64Image = image.buffer.toString('base64');
              console.log('Base64 encoded imagepath:', base64Image);
              return [
                memberIds[index],
                base64Image,
                imgIndex + 1
              ];
            });
          });

          const addImagesQuery = 'INSERT INTO productimages (productid, imagepath, image_order) VALUES ?';

          connection.query(addImagesQuery, [imageValues], (err) => {
            if (err) {
              console.error('Error adding images to the database:', err);
              res.status(500).json({ error: err.message });
            } else {
              console.log('Images added to the database:', imageValues);
              console.log('Redirecting to create category page. AdminId:', adminid);
              res.redirect(`/createcategory`);
            }
          });
        });
      });
    }
  });
});



app.get('/editcategory/:id', (req, res) => {
  const categoryId = req.params.id;

  connection.query('SELECT * FROM category WHERE id = ?', [categoryId], (error, results) => {
    if (error) {
      console.error('Error querying database:', error);
      return res.status(500).send('Error querying database');
    }
    if (results.length === 0) {
      return res.status(404).send('Category not found');
    }

    const adminId = req.session.adminId;

    if (!adminId) {
      console.error('Admin ID not found in session');
      res.status(401).send('Unauthorized');
      return;
    }

    const adminNameQuery = 'SELECT adminname, admincategory FROM admin WHERE adminid = ?';
    connection.query(adminNameQuery, [adminId], (adminError, adminResult) => {
      if (adminError) {
        console.error('Error fetching admin name: ' + adminError);
        res.status(500).send('Internal Server Error');
        return;
      }
    
      if (!adminResult || adminResult.length === 0) {
        console.error('Admin not found for adminId: ' + adminId);
        res.status(404).send('Admin not found');
        return;
      }
    
      const adminName = adminResult[0].adminname;
      const admincategory = adminResult[0].admincategory;
    res.render('editcategory', { hideDropdownItems: false, category: results[0],adminId, adminName, admincategory});
  });
});
});



app.post('/editcategory/:id', uploadMemory.single('imagePath'), (req, res) => {
  const categoryId = req.params.id;
  const { name } = req.body;

  if (req.file) {
      const imageFile = req.file;
      const base64Image = imageFile.buffer.toString('base64');
      updateCategory(categoryId, name, base64Image, res);
  } else {
      connection.query('SELECT imagepath FROM category WHERE id = ?', [categoryId], (err, result) => {
          if (err || result.length === 0) {
              console.error("Error fetching current image:", err);
              return res.status(500).json({ success: false, message: 'Failed to fetch current image' });
          }

          const imageBlob = result[0].imagepath;
          const base64Image = imageBlob.toString('base64');
          updateCategory(categoryId, name, base64Image, res);
      });
  }
});

function updateCategory(categoryId, name, imagePath, res) {
  if (!name || !imagePath) {
      return res.status(400).json({ success: false, message: 'Name and imagePath are required' });
  }

  connection.query(
      'UPDATE category SET name = ?, imagepath = ? WHERE id = ?',
      [name, imagePath, categoryId],
      (error, results) => {
          if (error) {
              console.error("Error updating category:", error);
              return res.status(500).json({ success: false, message: 'Failed to update category' });
          }

          console.log("Category updated successfully");
          res.status(200).json({ success: true, message: 'Category updated successfully' });
      }
  );
}

app.delete('/deletecategory/:id', (req, res) => {
  const categoryId = req.params.id;

  connection.query(
      'DELETE FROM category WHERE id = ?',
      [categoryId],
      (error, results) => {
          if (error) {
              console.error("Error deleting category:", error);
              return res.status(500).send("Error deleting category");
          }
          console.log("Category deleted successfully");
          res.sendStatus(200); 
      }
  );
});


app.get('/admindetails', (req, res) => {
  const adminId = req.session.adminId;

  connection.query('SELECT * FROM admin WHERE adminid = ?', [adminId], (error, adminResult) => {
      if (error) {
          console.error('Error fetching admin details:', error);
          res.status(500).send('Internal Server Error');
          return;
      }

      if (adminResult.length === 0) {
          res.status(404).send('Admin not found');
          return;
      }

      const adminName = adminResult[0].adminname;
      const admincategory = adminResult[0].admincategory;

      connection.query('SELECT * FROM admin', (error, allAdminsResult) => {
          if (error) {
              console.error('Error fetching all admin details:', error);
              res.status(500).send('Internal Server Error');
              return;
          }

          res.render('admindetails', { hideDropdownItems: false, adminName: adminName, admincategory:admincategory, adminId: adminId, adminDetails: allAdminsResult });
      });
  });
});

app.get('/editadmin/:adminId', (req, res) => {
  const adminId = req.params.adminId;

  connection.query('SELECT * FROM admin WHERE adminid = ?', [adminId], (error, results) => {
      if (error) {
          console.error('Error fetching admin details:', error);
          res.status(500).json({ error: 'Internal Server Error' });
          return;
      }
      if (results.length === 0) {
          res.status(404).json({ error: 'Admin not found' });
          return;
      }
      res.json(results[0]);
  });
});


app.post('/updateadmin', async (req, res) => {
  const { adminId, mobileNumber, password, adminName } = req.body;
  console.log('Received update admin:', adminId, mobileNumber, password, adminName );

  try {
      let query;
      let values;

      if (password) {
          const hashedPassword = await bcrypt.hash(password, 10);
          query = 'UPDATE admin SET mobilenumber = ?, password = ?, adminname = ? WHERE adminid = ?';
          values = [mobileNumber, hashedPassword, adminName, adminId];
      } else {
          query = 'UPDATE admin SET mobilenumber = ?, adminname = ? WHERE adminid = ?';
          values = [mobileNumber, adminName, adminId];
      }

      connection.query(query, values, (error, results) => {
          if (error) {
              console.error('Error updating admin details:', error);
              res.status(500).json({ success: false, message: 'Internal Server Error' });
              return;
          }
          res.json({ success: true, message: 'Admin details updated successfully' });
      });
  } catch (error) {
      console.error('Error updating admin details:', error);
      res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

app.post('/createadmin', async (req, res) => {
  const { mobileNumber, password, adminName, admincategory } = req.body;
  console.log('Received create admin:', mobileNumber, password, adminName,admincategory );

  try {
      if (!password) {
          throw new Error('Password is missing');
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      connection.query(
          'INSERT INTO admin (mobilenumber, password, adminname, admincategory) VALUES (?, ?, ?, ?)', 
          [mobileNumber, hashedPassword, adminName, admincategory], 
          (error, results) => {
              if (error) {
                  console.error('Error creating admin:', error);
                  res.status(500).json({ success: false, message: 'Internal Server Error' });
                  return;
              }
              res.json({ success: true, message: 'New admin created successfully' });
          }
      );
  } catch (error) {
      console.error('Error creating admin:', error);
      res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});




app.delete('/deleteadmin/:adminid', (req, res) => {
  const adminId = req.params.adminid;
  deleteAdminById(adminId)
      .then(result => {
          if (result.affectedRows > 0) {
              res.json({ success: true });
          } else {
              res.json({ success: false });
          }
      })
      .catch(err => {
          console.error('Error deleting admin:', err);
          res.status(500).json({ success: false });
      });
});

function deleteAdminById(adminId) {
  return new Promise((resolve, reject) => {
      const query = 'DELETE FROM admin WHERE adminid = ?';
      connection.query(query, [adminId], (error, results) => {
          if (error) {
              return reject(error);
          }
          resolve(results);
      });
  });
}
app.get('/product/:productId', (req, res) => {
  const productId = parseInt(req.params.productId, 10);

  if (isNaN(productId)) {
    return res.status(400).json({ error: 'Invalid productId' });
  }

  console.log('Received productId:', productId);

  const query = `
    SELECT p.*, pi.imagepath
    FROM products AS p
    LEFT JOIN productimages AS pi ON p.productid = pi.productid
    WHERE p.productid = ? AND pi.image_order = (SELECT MIN(image_order) FROM productimages WHERE productid = ?);
  `;

  connection.query(query, [productId, productId], (err, results) => {
    if (err) {
      console.error('Error fetching product details:', err);
      return res.status(500).json({ error: 'Error fetching product details' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const product = results[0];

    res.render('product-details', { product });
  });
});


app.get('/userdetails', (req, res) => {
  const storeId = req.query.storeid;
  const adminId = req.query.adminId;

  const userSql = `
  SELECT u.*
  FROM usersignin u
  JOIN storesignin s ON u.pincode = s.storepincode
  WHERE s.storeid = ?
`;

  connection.query(userSql, [storeId], (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    } else {
      const storeNameQuery = 'SELECT name FROM storesignin WHERE storeid = ?';
      connection.query(storeNameQuery, [storeId], (storeNameError, storeNameResult) => {
        if (storeNameError) {
          console.error('Error fetching store name: ' + storeNameError);
          res.status(500).send('Internal Server Error');
        } else {
          const storeName = storeNameResult[0].name;

          const adminNameQuery = 'SELECT adminname, admincategory FROM admin WHERE adminId = ?'; 

connection.query(adminNameQuery, [adminId], (adminNameError, adminNameResult) => {
  if (adminNameError) {
    console.error('Error fetching admin name: ' + adminNameError);
    res.status(500).send('Internal Server Error');
  } else {
    const adminName = adminNameResult[0].adminname; 
    const admincategory = adminNameResult[0].admincategory; 

    res.render('userdetails', {
      hideDropdownItems: false,
      userDetails: results,
      adminId: adminId,
      storeId: storeId, 
      storeName: storeName,
      adminName: adminName,
      admincategory: admincategory 
              });
            }
          });
        }
      });
    }
  });
});


app.post('/updateuser', (req, res) => {
  const userId = req.body.userId;
  const access = req.body.access;

  const updateQuery = 'UPDATE usersignin SET access = ? WHERE idusersignin = ?';

  connection.query(updateQuery, [access, userId], (error, results) => {
    if (error) {
      console.error('Error updating access: ' + error);
      return res.json({
        success: false,
        message: 'Failed to update access.'
      });
    }
    return res.json({
      success: true,
      message: 'Access updated successfully.'
    });
  });
});


app.get('/adminuserdetails', (req, res) => {
  const adminId = req.query.adminid;
  const filter = req.query.filter || 'all'; 
  const page = parseInt(req.query.page || 1);
  const pageSize = 15;
  const offset = (page - 1) * pageSize;

  if (!adminId) {
    return res.status(400).send('Invalid adminid');
  }

  let countQuery = 'SELECT COUNT(*) AS totalUsersCount FROM usersignin';
  let queryParams = [];

  if (filter !== 'all') {
    countQuery += ' WHERE access = ?';
    queryParams.push(filter === 'yes' ? 1 : 0);
  }

  connection.query(countQuery, queryParams, (countError, countResults) => {
    if (countError) {
      console.error('Error counting users: ', countError);
      return res.status(500).send('Internal Server Error: ' + countError.message);
    }

    const totalUsersCount = countResults[0].totalUsersCount;
    const totalPages = Math.ceil(totalUsersCount / pageSize);

    let query = `
      SELECT u.*, s.name AS storeName, s.place AS storePlace
      FROM usersignin u
      LEFT JOIN (
        SELECT DISTINCT storepincode, name, place 
        FROM storesignin
      ) s ON FIND_IN_SET(u.pincode, s.storepincode) > 0
      ${filter !== 'all' ? 'WHERE u.access = ?' : ''}
      LIMIT ? OFFSET ?;
    `;

    let queryParamsForUsers = filter !== 'all'
      ? [filter === 'yes' ? 1 : 0, pageSize, offset]
      : [pageSize, offset];

    connection.query(query, queryParamsForUsers, (error, results) => {
      if (error) {
        console.error('Error fetching user details: ', error);
        return res.status(500).send('Internal Server Error: ' + error.message);
      }

      const adminNameQuery = 'SELECT adminname, admincategory FROM admin WHERE adminid = ?';

      connection.query(adminNameQuery, [adminId], (adminNameError, adminNameResult) => {
        if (adminNameError) {
          console.error('Error fetching admin name: ', adminNameError);
          return res.status(500).send('Internal Server Error: ' + adminNameError.message);
        }

        if (!adminNameResult.length) {
          return res.status(404).send('Admin not found');
        }

        const adminName = adminNameResult[0].adminname;
        const admincategory = adminNameResult[0].admincategory;
        const startSerialNumber = (page - 1) * pageSize + 1;

        res.render('adminuserdetails', {
          hideDropdownItems: false,
          userDetails: results,
          totalPages: totalPages,
          currentPage: page,
          pageSize: pageSize,
          totalUsersCount: totalUsersCount,
          adminName: adminName,
          admincategory: admincategory,
          adminId: adminId,
          startSerialNumber: startSerialNumber,
          filter: filter 
        });
      });
    });
  });
});


app.get('/useradmin', (req, res) => {
  const adminId = req.query.adminid;
  const filter = req.query.filter || 'all'; 
  const page = parseInt(req.query.page || 1);
  const pageSize = 15;
  const offset = (page - 1) * pageSize;

  if (!adminId) {
    return res.status(400).send('Invalid adminid');
  }

  let countQuery = 'SELECT COUNT(*) AS totalUsersCount FROM usersignin';
  let queryParams = [];

  if (filter !== 'all') {
    countQuery += ' WHERE access = ?';
    queryParams.push(filter === 'yes' ? 1 : 0);
  }

  connection.query(countQuery, queryParams, (countError, countResults) => {
    if (countError) {
      console.error('Error counting users: ', countError);
      return res.status(500).send('Internal Server Error: ' + countError.message);
    }

    const totalUsersCount = countResults[0].totalUsersCount;
    const totalPages = Math.ceil(totalUsersCount / pageSize);

    let query = `
      SELECT u.*, s.name AS storeName, s.place AS storePlace
      FROM usersignin u
      LEFT JOIN (
        SELECT DISTINCT storepincode, name, place 
        FROM storesignin
      ) s ON FIND_IN_SET(u.pincode, s.storepincode) > 0
      ${filter !== 'all' ? 'WHERE u.access = ?' : ''}
      LIMIT ? OFFSET ?;
    `;

    let queryParamsForUsers = filter !== 'all'
      ? [filter === 'yes' ? 1 : 0, pageSize, offset]
      : [pageSize, offset];

    connection.query(query, queryParamsForUsers, (error, results) => {
      if (error) {
        console.error('Error fetching user details: ', error);
        return res.status(500).send('Internal Server Error: ' + error.message);
      }

      const adminNameQuery = 'SELECT adminname,admincategory FROM admin WHERE adminid = ?';

      connection.query(adminNameQuery, [adminId], (adminNameError, adminNameResult) => {
        if (adminNameError) {
          console.error('Error fetching admin name: ', adminNameError);
          return res.status(500).send('Internal Server Error: ' + adminNameError.message);
        }

        if (!adminNameResult.length) {
          return res.status(404).send('Admin not found');
        }

        const adminName = adminNameResult[0].adminname;
        const admincategory = adminNameResult[0].admincategory;

        const startSerialNumber = (page - 1) * pageSize + 1;

        res.render('useradmin', {
          hideDropdownItems:true,
          userDetails: results,
          totalPages: totalPages,
          currentPage: page,
          pageSize: pageSize,
          totalUsersCount: totalUsersCount,
          adminName: adminName,
          admincategory: admincategory,
          adminId: adminId,
          startSerialNumber: startSerialNumber,
          filter: filter 
        });
      });
    });
  });
});


app.post('/updateAccess', (req, res) => {
  const userId = req.body.userId;
  const access = req.body.access;
  const adminId = req.body.adminId; 

  const updateQuery = 'UPDATE usersignin SET access = ? WHERE idusersignin = ?';

  connection.query(updateQuery, [access, userId], (error, results) => {
    if (error) {
      console.error('Error updating access: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    res.redirect(`/useradmin?adminid=${adminId}`);
  });
});


app.get('/adminusersignup', (req, res) => {
  const adminId = req.query.adminid;

  if (!adminId) {
      console.error('Invalid adminId:', adminId);
      res.status(400).send('Invalid adminid');
      return;
  }

  connection.query('SELECT adminname, admincategory FROM admin WHERE adminid = ?', [adminId], (error, adminResult) => {
      if (error) {
          console.error('Error fetching admin details:', error);
          res.status(500).send('Internal Server Error');
          return;
      }

      if (adminResult.length === 0) {
          res.status(404).send('Admin not found');
          return;
      }

      const adminName = adminResult[0].adminname;
      const admincategory = adminResult[0].admincategory;

      res.render('adminusersignup', { 
          adminId, 
          adminName, 
          admincategory 
      });
  });
});


app.post('/adminuserregister', (req, res) => {
  const { name, mobilenumber, address, pincode, username, password, adminId } = req.body;

  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing password: ', err);
      res.status(500).json({ success: false, message: "An error occurred. Please try again later." });
      return;
    }

    const checkMobileNumberQuery = `
      SELECT mobilenumber FROM storesignin WHERE mobilenumber = ? 
      UNION 
      SELECT mobilenumber FROM admin WHERE mobilenumber = ? 
      UNION 
      SELECT mobilenumber FROM usersignin WHERE mobilenumber = ?
    `;

    connection.query(checkMobileNumberQuery, [mobilenumber, mobilenumber, mobilenumber], (err, results) => {
      if (err) {
        console.error('Error querying the database: ', err);
        res.status(500).json({ success: false, message: "An error occurred. Please try again later." });
        return;
      }

      if (results.length > 0) {
        res.render('usermobileerror');
      } else {
        const insertQuery = `
          INSERT INTO usersignin (name, mobilenumber, address, pincode, email, password) 
          VALUES (?, ?, ?, ?, ?, ?)
        `;
        connection.query(insertQuery, [name, mobilenumber, address, pincode, username || null, hashedPassword], (err, result) => {
          if (err) {
            console.error('Error inserting data into the database: ', err);
            res.status(500).json({ success: false, message: "An error occurred. Please try again later." });
            return;
          }
          res.render('adminuserregistersuccess', { adminId });
        });
      }
    });
  });
});



app.get('/adminedituser/:userid', (req, res) => {
  const userId = req.params.userid;
  const adminId = req.query.adminid; 

  const userQuery = 'SELECT * FROM usersignin WHERE idusersignin = ?';
  connection.query(userQuery, [userId], (error, userResults) => {
    if (error) {
      console.error('Error fetching user details:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (userResults.length === 0) {
      res.status(404).send('User not found');
      return;
    }

    const user = userResults[0];

    const adminQuery = 'SELECT adminName, admincategory FROM admin WHERE adminId = ?';
    connection.query(adminQuery, [adminId], (adminError, adminResults) => {
      if (adminError) {
        console.error('Error fetching admin details:', adminError);
        res.status(500).send('Internal Server Error');
        return;
      }
    
      if (adminResults.length === 0) {
        res.status(404).send('Admin not found');
        return;
      }
    
      const adminName = adminResults[0].adminName;
      const admincategory = adminResults[0].admincategory; 
    
      res.render('adminedituser', { hideDropdownItems: false, user, userId, adminId, adminName, admincategory });
    });
    
  });
});



app.post('/adminedituser/:userid', (req, res) => {
  const userId = req.params.userid;
  const adminId = req.query.adminid; 
  const { name, mobilenumber, address, pincode, email, password } = req.body;

  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing password:', err);
      res.status(500).send('Internal Server Error');
      return;
    }

    const query = 'UPDATE usersignin SET name = ?, mobilenumber = ?, address = ?, pincode = ?, email = ?, password = ? WHERE idusersignin = ?';
    connection.query(query, [name, mobilenumber, address, pincode, email, hashedPassword, userId], (error, results) => {
      if (error) {
        console.error('Error updating user details:', error);
        res.status(500).send('Failed to update user details. Please try again.');
        return;
      }
      res.render('admineditusersuccess', { adminId });
    });
  });
});


app.delete('/admindeleteuser/:userid', (req, res) => {
  const userId = req.params.userid;
  const adminId = req.query.adminid;

  const query = 'DELETE FROM usersignin WHERE idusersignin = ?';
  connection.query(query, [userId], (error, results) => {
    if (error) {
      console.error('Error deleting user:', error);
      res.status(500).json({ success: false, message: 'Failed to delete user. Please try again.' });
      return;
    }

    if (results.affectedRows > 0) {
      res.json({ success: true, message: 'User deleted successfully.' });
    } else {
      res.status(404).json({ success: false, message: 'User not found.' });
    }
  });
});


app.get('/confirmdeletestore/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  connection.query('SELECT * FROM storesignin WHERE storeId = ?', [storeId], (error, results) => {
    if (error) {
      console.error('Error fetching store details: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }
    const store = results[0];
    if (!store) {
      res.status(404).send('Store not found');
      return;
    }
    res.render('admindeleteconfirm', { store: store, storeId: storeId });
  });
});



app.get('/deletestore/:storeid', (req, res) => {
  const storeId = req.params.storeid;

  connection.query('SELECT productid FROM products WHERE storeId = ?', [storeId], (error, products) => {
    if (error) {
      console.error('Error fetching products: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    const productIds = products.map((product) => product.productid);

    if (productIds.length === 0) {
      continueDeletion();
    } else {
      const deleteCartItemsQuery = 'DELETE FROM cart WHERE productid IN (?)';
      connection.query(deleteCartItemsQuery, [productIds], (error) => {
        if (error) {
          console.error('Error removing cart items: ' + error);
          res.status(500).send('Internal Server Error');
          return;
        }

        continueDeletion();
      });
    }

    function continueDeletion() {
      connection.query('DELETE FROM products WHERE storeId = ?', [storeId], (error) => {
        if (error) {
          console.error('Error deleting products: ' + error);
          res.status(500).send('Internal Server Error');
          return;
        }

        connection.query('SELECT * FROM storesignin WHERE storeId = ?', [storeId], (error, results) => {
          if (error) {
            console.error('Error fetching store details: ' + error);
            res.status(500).send('Internal Server Error');
            return;
          }

          const store = results[0];

          connection.query('DELETE FROM storesignin WHERE storeId = ?', [storeId], (error) => {
            if (error) {
              console.error('Error deleting store: ' + error);
              res.status(500).send('Internal Server Error');
              return;
            }
            res.redirect('/adminstoredetails');
          });
        });
      });
    }
  });
});

app.post('/deletestore/:storeid', (req, res) => {
  const storeid = req.params.storeid;

  connection.query('DELETE FROM storesignin WHERE storeid = ?', [storeid], (error, results) => {
    if (error) {
      console.error('Error deleting store details: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }
    res.redirect('/adminstoredetails');
  });
});




app.post('/updatestore/:storeid', (req, res) => {
  const storeid = req.params.storeid;
  const { name,contactname, place, gstnumber, mobilenumber, pincode, password } = req.body;

  const sql = 'UPDATE storesignin SET name=?,contactname=?, place=?, gstnumber=?, mobilenumber=?, password=? WHERE storeid=?';
  connection.query(
    sql,
    [name,contactname, place, gstnumber, mobilenumber, password, storeid],
    (error, results) => {
      if (error) {
        console.error('Error updating store details: ' + error);
        res.status(500).send('Internal Server Error');
        return;
      }
      console.log('Store details updated successfully');
      res.redirect('/adminstoredetails');
    }
  );
});


app.get('/adminproductdetails', (req, res) => {
  const adminId = req.query.adminid;
  const search = req.query.search || '';
  const category = req.query.category || '';

  req.session.adminId = adminId;

  console.log('adminId:', adminId);
  
  // Query to count the total products for pagination
  const countQuery = 'SELECT COUNT(DISTINCT p.productid) AS totalProductsCount FROM products p';
  connection.query(countQuery, (countError, countResults) => {
    if (countError) {
      console.error('Error counting products: ' + countError);
      res.status(500).send('Internal Server Error');
      return;
    }

    const totalProductsCount = countResults[0].totalProductsCount;

    // Query to get admin name and category
    const adminNameQuery = 'SELECT adminname, admincategory FROM admin WHERE adminid = ?';
    connection.query(adminNameQuery, [adminId], (adminError, adminResult) => {
      if (adminError) {
        console.error('Error fetching admin name: ' + adminError);
        res.status(500).send('Internal Server Error');
        return;
      }

      if (adminResult.length === 0) {
        res.status(404).send('Admin not found');
        return;
      }

      const adminName = adminResult[0].adminname;
      const admincategory = adminResult[0].admincategory;

      const searchTerm = req.query.search || '';
      let sort = req.query.sort || 'default';
      let isAscending = req.query.isAscending === 'true'; 
      let sortKey = req.query.sortKey || 'productid'; 

      let query = `
      SELECT p.*, pi.imagepath
      FROM products p
      LEFT JOIN (
        SELECT productid, imagepath
        FROM (
          SELECT productid, imagepath, ROW_NUMBER() OVER (PARTITION BY productid ORDER BY image_order) as row_num
          FROM productimages
        ) ranked_images
        WHERE row_num = 1
      ) pi ON p.productid = pi.productid
    `;
    
    const queryParams = [];
    
    if (searchTerm) {
      query += ` WHERE p.productname LIKE ? `;
      queryParams.push(`%${searchTerm}%`);
    }
    
    if (category) {
      query += searchTerm ? ` AND ` : ` WHERE `;
      query += ` p.category = ? `;
      queryParams.push(category);
    }
    
    if (sortKey === 'productname') {
      query += isAscending ? ' ORDER BY p.productname ASC' : ' ORDER BY p.productname DESC';
    } else if (sortKey === 'category') {
      query += isAscending ? ' ORDER BY p.category ASC' : ' ORDER BY p.category DESC';
    } else if (sortKey === 'salesprice') {
      query += isAscending ? ' ORDER BY p.salesprice ASC' : ' ORDER BY p.salesprice DESC';
    } else if (sortKey === 'qty') {
      query += isAscending ? ' ORDER BY p.qty ASC' : ' ORDER BY p.qty DESC';
    } else {
      query += ' ORDER BY p.productid'; 
    }
    
    const page = req.query.page || 1;
    const pageSize = 16;
    const offset = (page - 1) * pageSize;
    
    query += ` LIMIT ? OFFSET ?; `;
    queryParams.push(pageSize, offset);

    // Query to get all product details for stock value calculation
    const allProductsQuery = `
      SELECT p.salesprice, p.qty
      FROM products p
      LEFT JOIN (
        SELECT productid, imagepath
        FROM (
          SELECT productid, imagepath, ROW_NUMBER() OVER (PARTITION BY productid ORDER BY image_order) as row_num
          FROM productimages
        ) ranked_images
        WHERE row_num = 1
      ) pi ON p.productid = pi.productid
      ${searchTerm ? 'WHERE p.productname LIKE ? ' : ''}
      ${category ? (searchTerm ? 'AND ' : 'WHERE ') + 'p.category = ? ' : ''}
    `;
    
    const allQueryParams = [];
    if (searchTerm) allQueryParams.push(`%${searchTerm}%`);
    if (category) allQueryParams.push(category);
    
    connection.query(allProductsQuery, allQueryParams, (allProductsError, allProductsResults) => {
      if (allProductsError) {
        console.error('Error fetching all product details: ' + allProductsError);
        res.status(500).send('Internal Server Error');
        return;
      }

      // Calculate overall stock value
      const overallStockValue = allProductsResults.reduce((total, product) => {
        return total + (product.salesprice * product.qty);
      }, 0);

      connection.query(query, queryParams, (error, results) => {
        if (error) {
            console.error('Error fetching product details: ' + error);
            res.status(500).send('Internal Server Error');
            return;
        }
    
        const productsWithImages = results.map(product => {
            const imageBase64 = product.imagepath && Buffer.isBuffer(product.imagepath)
                ? product.imagepath.toString('base64') 
                : null; 
    
            let decodedImagePath;
            if (imageBase64) {
                decodedImagePath = Buffer.from(imageBase64, 'base64');
            }
            return {
                ...product,
                imagepath: decodedImagePath
                    ? `data:image/jpeg;base64,${decodedImagePath}`  
                    : '/images/default-product.jpg' 
            };
        });
    
        const totalPages = Math.ceil(totalProductsCount / pageSize);
        const startSerialNumber = (page - 1) * pageSize + 1;
    
        const categoryQuery = 'SELECT DISTINCT category FROM products';
        connection.query(categoryQuery, (categoryError, categoryResults) => {
            if (categoryError) {
                console.error('Error fetching categories: ' + categoryError);
                res.status(500).send('Internal Server Error');
                return;
            }
    
            const categories = categoryResults.map(category => category.category);
            const selectedCategory = category;
    
            res.render('adminproductdetails', {
                hideDropdownItems: false,
                productDetails: productsWithImages,
                totalPages: totalPages,
                currentPage: page,
                pageSize: pageSize,
                totalProductsCount: totalProductsCount,
                totalStockValue: overallStockValue, // Include the overall stock value here
                adminId: adminId,
                adminName: adminName,
                admincategory: admincategory,
                startSerialNumber: startSerialNumber,
                search: search,
                sort: sort,
                isAscending: isAscending,
                sortKey: sortKey,
                categories: categories,
                selectedCategory: selectedCategory   
            });
          });
        });
      });
    });
  });
});



app.get('/getFilteredProductCount', (req, res) => {
  const { search, category } = req.query;
  const queryParams = [];
  let query = 'SELECT COUNT(*) AS filteredProductsCount FROM products WHERE 1=1';

  if (search) {
    query += ' AND productname LIKE ?';
    queryParams.push(`%${search}%`);
  }
  if (category) {
    query += ' AND category = ?';
    queryParams.push(category);
  }

  connection.query(query, queryParams, (error, results) => {
    if (error) {
      console.error('Error fetching filtered product count:', error);
      res.status(500).json({ error: 'Internal server error' });
    } else {
      const filteredProductsCount = results[0].filteredProductsCount;
      res.json({ filteredProductsCount });
    }
  });
});


app.get('/getSearchedProductCount', (req, res) => {
  const { search } = req.query;

  connection.query('SELECT COUNT(*) AS searchedProductsCount FROM products WHERE productname LIKE ?', [`%${search}%`], (error, results) => {
    if (error) {
      console.error('Error fetching searched product count:', error);
      res.status(500).json({ error: 'Internal server error' });
    } else {
      const searchedProductsCount = results[0].searchedProductsCount;

      res.json({ searchedProductsCount });
    }
  });
});

process.on('SIGINT', () => {
  console.log('Closing database connection...');
  connection.end((err) => {
    if (err) {
      console.error('Error closing database connection:', err);
      
    } else {
      console.log('Database connection closed');
      process.exit(0); 
    }
  });
});


app.get('/admineditproduct', (req, res) => {
  const productID = req.query.productid;
  const adminId = req.query.adminid;
  const parentId = req.query.parentid;

  const productQuery = 'SELECT * FROM products WHERE productid = ?';
  connection.query(productQuery, [productID], (productError, product) => {
    if (productError) {
      console.error('Error fetching product details:', productError);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (product.length === 0) {
      console.warn('Product not found');
      res.status(404).send('Product not found');
      return;
    }

    const productname = product[0].productname;

    const adminNameQuery = 'SELECT adminname, admincategory FROM admin WHERE adminid = ?';
    connection.query(adminNameQuery, [adminId], (adminError, admin) => {
      if (adminError) {
        console.error('Error fetching admin name:', adminError);
        res.status(500).send('Internal Server Error');
        return;
      }

      if (admin.length === 0) {
        console.warn('Admin not found');
        res.status(404).send('Admin not found');
        return;
      }

      const imageQuery = 'SELECT imagepath FROM productimages WHERE productid = ?';
      connection.query(imageQuery, [productID], (imageError, imageResult) => {
        if (imageError) {
          console.error('Error fetching image paths:', imageError);
          res.status(500).send('Internal Server Error');
          return;
        }

        const images = imageResult.map(image => {
          if (image && image.imagepath) {
            const base64Image = image.imagepath.toString(); 
            return `data:image/jpeg;base64,${base64Image}`; 
          }
          return ''; 
        });

        const adminDetailsQuery = 'SELECT * FROM admin';
        connection.query(adminDetailsQuery, (adminDetailsError, adminDetails) => {
          if (adminDetailsError) {
            console.error('Error fetching admin details:', adminDetailsError);
            res.status(500).send('Internal Server Error');
            return;
          }

          const allProductsQuery = 'SELECT * FROM products';
          connection.query(allProductsQuery, (allProductsError, allProducts) => {
            if (allProductsError) {
              console.error('Error fetching all products:', allProductsError);
              res.status(500).send('Internal Server Error');
              return;
            }

            res.render('admineditproduct', {
              hideDropdownItems: false,
              product: product[0],
              productname: productname,
              adminId: adminId,
              adminName: admin[0].adminname,
              admincategory: admin[0].admincategory,
              productImages: images, 
              adminDetails: adminDetails,
              products: allProducts,
              parentId: parentId,
              page: req.query.page || 1 
            });
          });
        });
      });
    });
  });
});


app.post('/admineditproduct', uploadMemory.array('images', 4), (req, res) => {
  const { parentid, hsn, code, gst, weight, salesprice, quantity } = req.body;
  const images = req.files;

  const producttype = 'member';
  const validSalesPrice = salesprice ? parseFloat(salesprice) : 0;
  const validQuantity = quantity ? parseInt(quantity) : 0;
  const validGst = gst ? parseFloat(gst) : 0;

  const parentProductQuery = 'SELECT GST, category, productname, description FROM products WHERE parentid = ? LIMIT 1';

  connection.query(parentProductQuery, [parentid], (parentProductError, parentProduct) => {
    if (parentProductError) {
      console.error('Error fetching parent product details:', parentProductError);
      return res.status(500).send({ message: 'Internal Server Error' });
    }

    if (parentProduct.length === 0) {
      console.error('Parent product not found for productid:', parentid);
      return res.status(404).send({ message: 'Parent Product Not Found' });
    }

    const { GST, category, productname, description } = parentProduct[0];

    const addMemberQuery = 'INSERT INTO products (parentid, producttype, productname, category, hsn, code, gst, weight, salesprice, qty, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

    connection.query(addMemberQuery, [parentid, producttype, productname, category, hsn, code, GST, weight, validSalesPrice, validQuantity, description], (err, results) => {
      if (err) {
        console.error('Error adding member product:', err);
        return res.status(500).json({ success: false, message: 'Failed to add new product' });
      }

      const productId = results.insertId;

      if (images.length === 0) {
        return res.status(400).json({ error: 'No images uploaded' });
      }

      connection.query('SELECT MAX(image_order) AS maxImageOrder FROM productimages WHERE productid = ?', [productId], (err, rows) => {
        if (err) {
          console.error('Error getting max image_order:', err);
          return res.status(500).json({ error: err.message });
        }

        const maxImageOrder = rows[0].maxImageOrder || 0;

        const imageValues = images.map((image, index) => {
          const base64Image = image.buffer.toString('base64');
          return [
            productId,
            base64Image, 
            maxImageOrder + index + 1
          ];
        });

        const addImagesQuery = 'INSERT INTO productimages (productid, imagepath, image_order) VALUES ?';

        connection.query(addImagesQuery, [imageValues], (err) => {
          if (err) {
            console.error('Error adding images to the database:', err);
            return res.status(500).json({ error: err.message });
          } else {
            return res.json({ success: true, message: 'Product updated successfully' });
          }
        });
      });
    });
  });
});


app.post(
  '/adminupdateproduct',
  uploadMemory.fields([
    { name: 'newFileInput0', maxCount: 1 },
    { name: 'newFileInput1', maxCount: 1 },
    { name: 'newFileInput2', maxCount: 1 },
    { name: 'newFileInput3', maxCount: 1 }
  ]),
  (req, res) => {
    const productID = req.body.productid;
    const newImages = req.files;

    console.log('Uploaded files:', newImages);

    let completedUpdates = 0;
    const totalImages = Object.keys(newImages).length;
    const updatedImages = [];

    if (totalImages > 0) {
      Object.keys(newImages).forEach((key, index) => {
        const newImage = newImages[key] ? newImages[key][0] : null;

        if (newImage) {
          console.log(`Processing image ${index} with original name: ${newImage.originalname}`);

          if (newImage.buffer) {
            const newImageBuffer = newImage.buffer;
            const base64Image = newImageBuffer.toString('base64');

            const fetchImagePathQuery =
              'SELECT imagepath FROM productimages WHERE productid = ? AND image_order = ?';
            connection.query(
              fetchImagePathQuery,
              [productID, index + 1],
              (fetchError, results) => {
                if (fetchError) {
                  console.error('Error fetching current image path: ' + fetchError);
                  return res
                    .status(500)
                    .json({ success: false, message: 'Failed to fetch current image path' });
                }

                const updateImagePathQuery =
                  'UPDATE productimages SET imagepath = ? WHERE productid = ? AND image_order = ?';
                connection.query(
                  updateImagePathQuery,
                  [base64Image, productID, index + 1],
                  (imageUpdateError) => {
                    if (imageUpdateError) {
                      console.error('Error updating image path: ' + imageUpdateError);
                      return res
                        .status(500)
                        .json({ success: false, message: 'Failed to update image paths' });
                    }

                    updatedImages.push(`data:image/jpeg;base64,${base64Image}`);
                    completedUpdates++;

                    if (completedUpdates === totalImages) {
                      proceedWithProductUpdate();
                    }
                  }
                );
              }
            );
          } else {
            console.warn(`No buffer found for image field ${key} (index ${index}), skipping...`);
            completedUpdates++;
            if (completedUpdates === totalImages) {
              proceedWithProductUpdate();
            }
          }
        } else {
          console.warn(`No image file found for image field ${key} (index ${index}), skipping...`);
          completedUpdates++;
          if (completedUpdates === totalImages) {
            proceedWithProductUpdate();
          }
        }
      });
    } else {
      proceedWithProductUpdate();
    }

    function proceedWithProductUpdate() {
      const updateData = {
        productname: req.body.productname,
        producttype: req.body.producttype,
        category: req.body.category,
        code: req.body.code,
        hsn: req.body.hsn,
        salesprice: req.body.salesprice,
        GST: req.body.gst,
        qty: req.body.quantity,
        description: req.body.description,
        weight: req.body.weight
      };

      const updateQuery = 'UPDATE products SET ? WHERE productid = ?';

      connection.query(updateQuery, [updateData, productID], (error) => {
        if (error) {
          console.error('Error updating product: ' + error);
          return res
            .status(500)
            .json({ success: false, message: 'Failed to update product details' });
        }

        res.json({
          success: true,
          message: 'Product updated successfully',
          updatedImages
        });
      });
    }
  }
);

app.delete('/admindeleteproduct', (req, res) => {
  const productID = req.query.productid;

  const deleteStoreProductsQuery = 'DELETE FROM storeproducts WHERE productid = ?';
  connection.query(deleteStoreProductsQuery, [productID], (storeError) => {
      if (storeError) {
          console.error('Error deleting related store products:', storeError);
          res.status(500).json({ success: false, message: 'Failed to delete related store products' });
          return;
      }

      const deleteProductImagesQuery = 'DELETE FROM productimages WHERE productid = ?';
      connection.query(deleteProductImagesQuery, [productID], (imageError) => {
          if (imageError) {
              console.error('Error deleting product images:', imageError);
              res.status(500).json({ success: false, message: 'Failed to delete product images' });
              return;
          }

          const deleteProductQuery = 'DELETE FROM products WHERE productid = ?';
          connection.query(deleteProductQuery, [productID], (productError) => {
              if (productError) {
                  console.error('Error deleting product:', productError);
                  res.status(500).json({ success: false, message: 'Failed to delete product' });
                  return;
              }

              res.json({ success: true, message: 'Product deleted successfully' });
          });
      });
  });
});

app.delete('/admindeleteproductfamily', (req, res) => {
  const productID = req.query.productid;

  const deleteProductImagesQuery = `
      DELETE FROM productimages 
      WHERE productid IN (
          SELECT productid 
          FROM products 
          WHERE parentid = ? OR productid = ?
      )`;

  connection.query(deleteProductImagesQuery, [productID, productID], (imagesError) => {
      if (imagesError) {
          console.error('Error deleting product images:', imagesError);
          res.status(500).json({ success: false, message: 'Failed to delete product images' });
          return;
      }

      const deleteMembersQuery = `
          DELETE FROM products 
          WHERE parentid = ? OR productid = ?`;

      connection.query(deleteMembersQuery, [productID, productID], (membersError) => {
          if (membersError) {
              console.error('Error deleting product family members:', membersError);
              res.status(500).json({ success: false, message: 'Failed to delete product family members' });
              return;
          }

          res.json({ success: true, message: 'Product family and its members deleted successfully' });
      });
  });
});


//user***********

//usersignup

app.use(express.urlencoded({ extended: true }));

app.get('/usersignup',
(req, res) => {
  res.sendFile(path.join(__dirname, 'views', '/usersignup.html'));
});


app.post('/register', (req, res) => {
  const { name, mobilenumber, address, pincode, username, password } = req.body;

  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing password: ', err);
      res.status(500).json({ success: false, message: "An error occurred. Please try again later." });
      return;
    }

    const query = `SELECT mobilenumber FROM usersignin WHERE mobilenumber = ? 
                  UNION 
                  SELECT mobilenumber FROM storesignin WHERE mobilenumber = ? 
                  UNION 
                  SELECT mobilenumber FROM admin WHERE mobilenumber = ?`;

    connection.query(query, [mobilenumber, mobilenumber, mobilenumber], (err, results) => {
      if (err) {
        console.error('Error querying the database: ', err);
        res.status(500).json({ success: false, message: "An error occurred. Please try again later." });
        return;
      }

      if (results.length > 0) {
        res.render('usermobileerror');
      } else {
        const insertQuery = `INSERT INTO usersignin (name, mobilenumber, address, pincode, email, password) VALUES (?, ?, ?, ?, ?, ?)`;
        connection.query(insertQuery, [name, mobilenumber, address, pincode, username, hashedPassword], (err, result) => {
          if (err) {
            console.error('Error inserting data into the database: ', err);
            res.status(500).json({ success: false, message: "An error occurred. Please try again later." });
            return;
          }
          res.render('registration-success');
        });
      }
    });
  });
});


app.get('/userstoredetails/:storeid', (req, res) => {
  const userId = req.query.userId;
  const storeId = req.params.storeid;
  const page = parseInt(req.query.page) || 1;
  const itemsPerPage = 16;
  const selectedCategory = req.query.category || '';
  const searchKeyword = req.query.search || '';

  const userQuery = `
    SELECT usersignin.name AS userName, storesignin.name AS storeName, storesignin.mobilenumber
    FROM usersignin
    JOIN storesignin ON storesignin.storeid = ?
    WHERE usersignin.idusersignin = ?`;

  connection.query(userQuery, [storeId, userId], (error, userResults) => {
    if (error) {
      console.error('Error fetching user and store:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (!userResults || userResults.length === 0) {
      return res.status(404).json({ error: 'User or store not found' });
    }
    const userName = userResults[0].userName;
    const storeName = userResults[0].storeName;
    const mobilenumber = userResults[0].mobilenumber;

    req.session.userId = userId;
    req.session.storeId = storeId;
    req.session.userName = userName;
    req.session.storeName = storeName;

    const storeProductQuery = 'SELECT productid FROM storeproducts WHERE storeid = ?';
    connection.query(storeProductQuery, [storeId], (error, storeProductResults) => {
      if (error) {
        console.error('Error fetching productid:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      const productIds = storeProductResults.map((sp) => sp.productid);

      if (productIds.length === 0) {
        const uniqueCategoriesQuery = 'SELECT DISTINCT category FROM products';
        connection.query(uniqueCategoriesQuery, (error, uniqueCategoriesResults) => {
          if (error) {
            console.error('Error fetching unique categories:', error);
            return res.status(500).json({ error: 'Internal Server Error' });
          }

          const uniqueCategories = uniqueCategoriesResults.map((category) => category.category);

          res.render('userstoredetails', {
            products: [],
            storeId,
            userId,
            userName,
            storeName,
            mobilenumber,
            currentPage: page,
            totalPages: 0, 
            selectedCategory,
            searchKeyword,
            categories: uniqueCategories,
            specialOffer: null,
          });          
        });
      } else {
        let productsQuery = `
          SELECT 
            p.productid AS productid, 
            p.productname AS productname, 
            p.category AS category, 
            p.code AS code, 
            p.hsn AS hsn, 
            COALESCE(
              NULLIF(p.parentid, -1),
              IFNULL(so.discountprice, p.salesprice)
            ) AS salesprice, 
            COALESCE(
              NULLIF(p.parentid, -1),
              p.weight
            ) AS weight, 
            p.GST AS GST, 
            COALESCE(
              NULLIF(p.parentid, -1),
              (
                SELECT IFNULL(s.qty, 0)
                FROM storeproducts s
                WHERE s.productid = p.productid AND s.storeid = ?
              )
            ) AS qty,  
            p.description AS description, 
            pi.imagepath AS imagepath,
            IF(p.parentid != -1, (
              SELECT JSON_ARRAYAGG(IFNULL(subSo.discountprice, sub.salesprice)) 
              FROM (
                SELECT p2.salesprice, p2.weight, p2.productid, p2.parentid
                FROM products p2
                WHERE p2.parentid = p.parentid
                ORDER BY p2.weight
              ) AS sub
              LEFT JOIN storeproducts sp2 ON sp2.productid = sub.productid AND sp2.storeid = ?
              LEFT JOIN specialoffers subSo ON sp2.offerid = subSo.offerid AND subSo.expirydate >= CURRENT_TIMESTAMP()
            ), NULL) AS salesprice_array,
            IF(p.parentid != -1, (
              SELECT JSON_ARRAYAGG(sub.weight) 
              FROM (
                SELECT p2.weight 
                FROM products p2
                WHERE p2.parentid = p.parentid
                ORDER BY p2.weight
              ) AS sub
            ), NULL) AS weight_array,
            IF(p.parentid != -1, (
              SELECT JSON_ARRAYAGG(IFNULL(sub.qty, 0)) 
              FROM (
                SELECT IFNULL(sp2.qty, 0) AS qty
                FROM products p2
                LEFT JOIN storeproducts sp2 ON sp2.productid = p2.productid AND sp2.storeid = ?
                WHERE p2.parentid = p.parentid
                ORDER BY p2.weight
              ) AS sub
            ), NULL) AS qty_array,
            IF(p.parentid != -1, (
              SELECT JSON_ARRAYAGG(sub.productid) 
              FROM (
                SELECT p2.productid 
                FROM products p2
                WHERE p2.parentid = p.parentid
                ORDER BY p2.weight
              ) AS sub
            ), NULL) AS productid_array,
            IF(p.parentid != -1, (
              SELECT JSON_ARRAYAGG(pi.imagepath)
              FROM products p2
              JOIN storeproducts s2 ON p2.productid = s2.productid
              JOIN productimages pi ON pi.productid = s2.productid
              WHERE p2.parentid = p.parentid
              ORDER BY p2.weight
            ), NULL) AS imagepath_array,
            so.content AS specialOfferContent,
            so.discountprice AS specialOfferDiscountPrice,
            so.expirydate AS specialOfferExpiryDate
          FROM 
            products p
          JOIN 
            storeproducts s ON p.productid = s.productid
          LEFT JOIN 
            productimages pi ON s.productid = pi.productid
          LEFT JOIN 
            specialoffers so ON s.offerid = so.offerid AND so.expirydate >= CURRENT_TIMESTAMP() 
          WHERE 
            s.productid IN (?) AND s.storeid = ?
            AND (
              p.producttype = 'product'
              OR p.productid = (
                SELECT min(m.productid)
                FROM products m
                WHERE m.parentid = p.parentid AND m.producttype = 'member'
              )
            )`;

        const queryParams = [storeId, storeId, storeId, productIds, storeId];

        if (selectedCategory) {
          productsQuery += ' AND p.category = ?';
          queryParams.push(selectedCategory);
        }

        if (searchKeyword) {
          productsQuery += ' AND p.productname LIKE ?';
          queryParams.push(`%${searchKeyword}%`);
        }

        productsQuery += `
          GROUP BY p.productid, p.productname, p.category, p.code, p.hsn, p.salesprice, p.GST, s.qty, p.description, pi.imagepath, so.content, so.discountprice, so.expirydate
          LIMIT ?, ?`;

        const offset = (page - 1) * itemsPerPage;
        queryParams.push(offset, itemsPerPage);

        connection.query(productsQuery, queryParams, (error, productResults) => {
          if (error) {
            console.error('Error fetching products:', error);
            return res.status(500).json({ error: 'Internal Server Error' });
          }

          const productsWithImages = productResults.map(product => {
            if (product.imagepath) {
              product.imagepath = `data:image/jpeg;base64,${product.imagepath}`; 
            }
            return product;
          });

          const uniqueCategoriesQuery = 'SELECT DISTINCT category FROM products';
          connection.query(uniqueCategoriesQuery, (error, uniqueCategoriesResults) => {
            if (error) {
              console.error('Error fetching unique categories:', error);
              return res.status(500).json({ error: 'Internal Server Error' });
            }

            const uniqueCategories = uniqueCategoriesResults.map((category) => category.category);
            const totalPages = Math.ceil(productIds.length / itemsPerPage);

            res.render('userstoredetails', {
              products: productsWithImages,
              storeId,
              userId,
              userName,
              storeName,
              mobilenumber,
              currentPage: page,
              totalPages,  
              selectedCategory,
              searchKeyword,  
              categories: uniqueCategories,
            });            
          });
        });
      }
    });
  });
});




app.get('/api/cart/count', (req, res) => {
  const userId = req.session.userId;

  const cartItemCountQuery = 'SELECT COUNT(*) AS count FROM cart WHERE userid = ?';

  connection.query(cartItemCountQuery, [userId], (error, results) => {
    if (error) {
      console.error('Error fetching cart item count:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    const count = results[0].count;

    res.json({ count });
  });
});



app.get('/productspage/:productid', (req, res) => {
  const productId = req.params.productid;
  const storeId = req.session.storeId;

  const productQuery = `
    SELECT 
      p.*, 
      so.content AS specialOfferContent,
      so.discountprice AS specialOfferDiscountPrice,
      so.expirydate AS specialOfferExpiryDate
    FROM 
      products p
    LEFT JOIN 
      storeproducts sp ON p.productid = sp.productid AND sp.storeid = ?
    LEFT JOIN 
      specialoffers so ON sp.offerid = so.offerid AND so.expirydate >= CURRENT_TIMESTAMP()
    WHERE 
      p.productid = ?`;

  connection.query(productQuery, [storeId, productId], (error, productResults) => {
    if (error) {
      console.error('Error retrieving product:', error);
      res.render('productspage', { product: null, images: [], userName: null, storeName: null, qty: null });
    } else {
      if (productResults.length > 0) {
        const product = productResults[0];
        const qtyQuery = 'SELECT qty FROM storeproducts WHERE productid = ? AND storeid = ?';

        connection.query(qtyQuery, [productId, storeId], (error, qtyResults) => {
          if (error) {
            console.error('Error fetching qty:', error);
            res.render('productspage', { product, images: [], userName: null, storeName: null, qty: null });
          } else {
            const qty = qtyResults.length > 0 ? qtyResults[0].qty : 0;

            const imageQuery = 'SELECT imagepath FROM productimages WHERE productid = ?';
            connection.query(imageQuery, [productId], (error, imageResults) => {
              if (error) {
                console.error('Error fetching images:', error);
                res.render('productspage', { product, images: [], userName: null, storeName: null, qty });
              } else {
          const  images = imageResults.map(image => ({
              imagepath: image.imagepath
                ? `data:image/jpeg;base64,${image.imagepath}`  
                : '', 
                }));

                const isOfferValid = product.specialOfferExpiryDate >= new Date();
                const specialOfferDiscountPrice = isOfferValid ? product.specialOfferDiscountPrice : null;

                res.render('productspage', {
                  product,
                  images,
                  userName: req.session.userName,
                  storeName: req.session.storeName,
                  userId: req.session.userId,
                  storeId,
                  qty,
                  specialOfferContent: isOfferValid ? product.specialOfferContent : null,
                  specialOfferDiscountPrice,
                  specialOfferExpiryDate: isOfferValid ? product.specialOfferExpiryDate : null
                });
              }
            });
          }
        });
      } else {
        console.log('Product not found for productid:', productId);
        res.render('productspage', { product: null, images: [], userName: null, storeName: null, qty: null });
      }
    }
  });
});




app.post('/buynow', (req, res) => {
  const productid = req.body.productid;
  const quantity = parseInt(req.body.quantity);
  const userid = req.session.userId; 
  const storeId = req.session.storeId; 
  if (!userid) {
    res.status(401).send('Unauthorized');
    return;
  }

  const checkCartQuery = 'SELECT * FROM cart WHERE userid = ? AND productid = ?';
  connection.query(checkCartQuery, [userid, productid], (error, results) => {
    if (error) {
      console.error('Error checking cart:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (results.length > 0) {
      console.log('Product is already in the cart. Updating quantity.');
      const updateQuantityQuery = 'UPDATE cart SET quantity = ? WHERE userid = ? AND productid = ?';
      connection.query(updateQuantityQuery, [quantity, userid, productid], (error) => {
        if (error) {
          console.error('Error updating cart quantity:', error);
          res.status(500).send('Internal Server Error');
          return;
        }
        console.log('Quantity updated. Redirecting to cart page.');
        res.redirect('/cart');
      });
    } else {
      console.log('Product is not in the cart. Adding a new item.');
      const insertCartQuery = 'INSERT INTO cart (userid, productid, quantity) VALUES (?, ?, ?)';
      connection.query(insertCartQuery, [userid, productid, quantity], (error) => {
        if (error) {
          console.error('Error adding to cart:', error);
          res.status(500).send('Internal Server Error');
          return;
        }
        console.log('Product added to the cart. Redirecting to cart page.');
        res.redirect('/cart');
      });
    }
  });
});


app.get('/cart', (req, res) => {
  const userId = req.session.userId; 
  const storeId = req.session.storeId; 

  if (!userId) {
    return res.status(400).send('User not logged in.');
  }

  const cartQuery = `
    SELECT 
      cart.cartid, 
      products.productid, 
      products.productname, 
      products.salesprice, 
      cart.quantity, 
      productimages.imagepath, 
      storeproducts.qty AS maxQuantity,
      COALESCE(specialoffers.discountprice, products.salesprice) AS finalPrice
    FROM 
      cart
    INNER JOIN 
      products ON cart.productid = products.productid
    INNER JOIN 
      storeproducts ON storeproducts.productid = products.productid AND storeproducts.storeid = ?
    INNER JOIN 
      productimages ON productimages.productid = storeproducts.productid
    LEFT JOIN 
      specialoffers ON storeproducts.offerid = specialoffers.offerid AND specialoffers.expirydate >= CURRENT_TIMESTAMP()
    WHERE 
      cart.userid = ?`;

  connection.query(cartQuery, [storeId, userId], (error, results) => {
    if (error) {
      console.error('Error retrieving cart items:', error);
      return res.status(500).send('Internal Server Error');
    } 

    const cartItems = results.map(item => ({
      ...item,
      imagepath: item.imagepath
        ? `data:image/jpeg;base64,${item.imagepath}` 
        : '', 
    }));

    const totalPrice = cartItems.reduce((total, item) => total + item.finalPrice * item.quantity, 0);

    const userQuery = `
      SELECT 
        usersignin.name AS userName, 
        storesignin.name AS storeName
      FROM 
        usersignin
      JOIN 
        storesignin ON FIND_IN_SET(usersignin.pincode, storesignin.storepincode) > 0
      WHERE 
        usersignin.idusersignin = ?`;

    connection.query(userQuery, [userId], (error, userResults) => {
      if (error) {
        console.error('Error fetching user details:', error);
        return res.status(500).send('Internal Server Error');
      } 
      if (userResults.length > 0) {
        const userName = userResults[0].userName;
        const storeName = userResults[0].storeName;

        console.log(`UserName: ${userName}`);

        res.render('cart', {
          cartItems,
          totalPrice,
          storeId,
          userId,     
          userName,
          storeName,
        });
      } else {
        console.log('User not found');
        return res.status(404).send('User not found');
      }
    });
  });
});




app.post('/cart', (req, res) => {
  const userId = req.session.userId;
  const storeId = req.session.storeId; 
  const { cartId, quantity } = req.body;

  const updateCartQuery = 'UPDATE cart SET quantity = ? WHERE cartid = ? AND userid = ?';
  connection.query(updateCartQuery, [quantity, cartId, userId], (error, results) => {
    if (error) {
      console.error('Error updating cart item:', error);
      res.status(500).send('Internal Server Error');
    } else {
      res.redirect('/cart');
    }
  });
});

app.post('/removefromcart', (req, res) => {
  const userId = req.session.userId;
  const cartId = req.body.cartid;

  const removeCartItemQuery = 'DELETE FROM cart WHERE cartid = ? AND userid = ?';
  connection.query(removeCartItemQuery, [cartId, userId], (error, results) => {
    if (error) {
      console.error('Error removing item from cart:', error);
      res.status(500).send('Internal Server Error');
    } else {
      const cartQuery = `
   SELECT cart.cartid, products.productid, products.productname, products.salesprice, cart.quantity, productimages.imagepath
        FROM cart
        INNER JOIN products ON cart.productid = products.productid
        INNER JOIN storeproducts ON storeproducts.productid = products.productid
        INNER JOIN productimages ON productimages.productid = storeproducts.productid
        WHERE cart.userid = ?
      `;

      connection.query(cartQuery, [userId], (error, results) => {
        if (error) {
          console.error('Error retrieving cart items:', error);
          res.status(500).send('Internal Server Error');
        } else {
          const cartItems = results;

          const totalPrice = cartItems.reduce((total, item) => total + item.salesprice * item.quantity, 0);

          res.status(200).json({ cartItems, totalPrice });
        }
      });
    }
  });
});

app.get('/checkout', (req, res) => {
  const userId = req.session.userId;
  const storeId = req.session.storeId;
  console.log('CHECK userId:', userId); 

  if (!userId) {
    return res.status(400).send('User is not logged in.');
  }

  const cartQuery = `
    SELECT 
      cart.cartid, 
      products.productid, 
      products.productname, 
      products.salesprice, 
      cart.quantity, 
      COALESCE(specialoffers.discountprice, products.salesprice) AS finalPrice
    FROM 
      cart
    INNER JOIN 
      products ON cart.productid = products.productid
    INNER JOIN 
      storeproducts ON storeproducts.productid = products.productid AND storeproducts.storeid = ?
    LEFT JOIN 
      specialoffers ON storeproducts.offerid = specialoffers.offerid AND specialoffers.expirydate >= CURRENT_TIMESTAMP() 
    WHERE 
      cart.userid = ?
  `;

  const userQuery = 'SELECT name, address, mobilenumber FROM usersignin WHERE idusersignin = ?';

  const storeQuery = `
    SELECT storesignin.name AS storename
    FROM storesignin
    INNER JOIN usersignin ON FIND_IN_SET(usersignin.pincode, storesignin.storepincode) > 0
    WHERE usersignin.idusersignin = ?
  `;
  
  connection.query(cartQuery, [storeId, userId], (error, cartResults) => {
    if (error) {
      console.error('Error retrieving cart items:', error);
      return res.status(500).send('Internal Server Error');
    }

    connection.query(userQuery, [userId], (userError, userResults) => {
      if (userError) {
        console.error('Error retrieving user details:', userError);
        return res.status(500).send('Internal Server Error');
      }

      if (!userResults || userResults.length === 0) {
        console.error('No user found with id:', userId);
        return res.status(404).send('User not found');
      }

      const user = {
        name: userResults[0].name,
        address: userResults[0].address,
        phoneNumber: userResults[0].mobilenumber,
      };

      connection.query(storeQuery, [userId], (storeError, storeResults) => {
        if (storeError) {
          console.error('Error retrieving store name:', storeError);
          return res.status(500).send('Internal Server Error');
        }

        if (!storeResults || storeResults.length === 0) {
          console.error('No store found for user id:', userId);
          return res.status(404).send('Store not found');
        }

        const cartItems = cartResults;
        const totalPrice = cartItems.reduce((total, item) => total + item.finalPrice * item.quantity, 0);

        const storeName = storeResults[0].storename;

        res.render('checkout', { 
          cartItems, 
          totalPrice, 
          user, 
          storeName,
          storeId,
          userName: user.name,
          userId 
        });
      });
    });
  });
});



app.post('/checkout', (req, res) => {

  const userId = req.session.userId;

  const clearCartQuery = 'DELETE FROM cart WHERE userid = ?';
  connection.query(clearCartQuery, [userId], (error) => {
    if (error) {
      console.error('Error clearing cart:', error);
      res.status(500).send('Internal Server Error');
    } else {
      res.render('checkout-success');
    }
  });
});

app.post('/placeorder', (req, res) => {
  const userId = req.session.userId;
  const storeId = req.session.storeId;
  console.log('place', storeId);
  const cartItems = JSON.parse(req.body.cartItems);
  const totalPrice = parseFloat(req.body.totalPrice.replace('₹', ''));

  const getOrderidQuery = 'SELECT MAX(CAST(orderid AS UNSIGNED)) AS maxOrderId FROM `order` WHERE storeid = ?';
  connection.query(getOrderidQuery, [storeId], (orderIdError, orderIdResult) => {
    if (orderIdError) {
      console.error('Error getting max orderid:', orderIdError);
      return res.status(500).send('Internal Server Error');
    }

    const currentOrderId = orderIdResult[0].maxOrderId || 0;
    const newOrderId = (currentOrderId + 1).toString().padStart(4, '0'); 

    const orderData = cartItems.map(item => {
      return {
        orderid: newOrderId,
        productid: item.productid,
        storeid: storeId,
        userid: userId,
        productname: item.productname,
        price: item.finalPrice,
        quantity: item.quantity,
        totalprice: item.finalPrice * item.quantity,
        status: 'Ordered',
        overallstatus: 'Ordered'
      };
    });

    const orderQuery = `
    INSERT INTO \`order\` (orderid, productid, storeid, userid, productname, price, quantity, totalprice, status, overallstatus) 
    VALUES ?`;

    connection.query(orderQuery, [orderData.map(order => Object.values(order))], (error, results) => {
      if (error) {
        console.error('Error placing the order:', error);
        return res.status(500).send('Internal Server Error');
      }

      for (const item of cartItems) {
        const updateQuantityQuery = 'UPDATE storeproducts SET qty = qty - ? WHERE productid = ? AND storeId = ?';
        connection.query(updateQuantityQuery, [item.quantity, item.productid, storeId], (quantityError) => {
          if (quantityError) {
            console.error('Error updating product quantity:', quantityError);
          }
        });
      }

      const clearCartQuery = 'DELETE FROM cart WHERE userid = ?';
      connection.query(clearCartQuery, [userId], (clearError) => {
        if (clearError) {
          console.error('Error clearing cart:', clearError);
        }
      });

      res.redirect(`/order-success?storeid=${storeId}&userid=${userId}`);
    });
  });
});



app.get('/order-success', (req, res) => {
  const storeId = req.query.storeid;
  const userId = req.query.userid;
  res.render('order-success', { storeId, userId });
});


app.get('/myorders', (req, res) => {
  const userId = req.session.userId;

  if (!userId) {
    return res.status(400).send('User ID is missing');
  }

  const orderQuery = `
    SELECT 
      orderid, 
      storeid, 
      orderdate, 
      SUM(totalprice) AS totalamount, 
      status
    FROM \`order\`
    WHERE userid = ? 
      AND orderdate >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)
    GROUP BY orderid, storeid, orderdate, status
    ORDER BY orderdate DESC 
    LIMIT 20`;

  connection.query(orderQuery, [userId], (orderErr, orderResults) => {
    if (orderErr) {
      console.error('Error querying orders:', orderErr);
      return res.status(500).send('Error querying orders');
    }

    if (orderResults.length === 0) {
      console.error('No orders found for this user.');
      return res.status(404).send('No orders found for this user.');
    }

    const storeId = orderResults[0].storeid;
    console.log('Order Results:', orderResults);

    const userNameQuery = 'SELECT name FROM usersignin WHERE idusersignin = ?';
    connection.query(userNameQuery, [userId], (userNameErr, userNameResult) => {
      if (userNameErr) {
        console.error('Error querying userName:', userNameErr);
        return res.status(500).send('Error querying userName');
      }

      const userName = userNameResult[0]?.name;

      const storeNameQuery = 'SELECT name FROM storesignin WHERE storeid = ?';
      connection.query(storeNameQuery, [storeId], (storeNameErr, storeNameResult) => {
        if (storeNameErr) {
          console.error('Error querying storeName:', storeNameErr);
          return res.status(500).send('Error querying storeName');
        }

        const storeName = storeNameResult[0]?.name;

        res.render('myorders', {
          userOrders: orderResults,
          userName: userName,
          storeName: storeName,
          storeId, 
          userId,  
        });
      });
    });
  });
});

app.get('/userorderdetails/:orderid', (req, res) => {
  const orderId = req.params.orderid; 
  const storeId = req.query.storeid;  
  const userId = req.session.userId;  

  if (!storeId) {
    return res.status(400).send('Store ID is missing in query parameters');
  }

  if (!userId) {
    return res.status(401).send('User ID is missing in session');
  }

  const orderDetailsQuery = `
    SELECT 
      productname, 
      price, 
      quantity, 
      orderdate, 
      totalprice, 
      status,
      overallstatus
    FROM \`order\`
    WHERE orderid = ? AND storeid = ?`;

  connection.query(orderDetailsQuery, [orderId, storeId], (err, results) => {
    if (err) {
      console.error('Error querying order details:', err);
      return res.status(500).send('Error querying order details');
    }

    if (results.length === 0) {
      console.error('No details found for the given order ID and store ID');
      return res.status(404).send('No details found for the given order ID');
    }

    const storeNameQuery = 'SELECT name FROM storesignin WHERE storeid = ?';
    connection.query(storeNameQuery, [storeId], (storeNameErr, storeNameResult) => {
      if (storeNameErr) {
        console.error('Error querying storeName:', storeNameErr);
        return res.status(500).send('Error querying storeName');
      }

      const storeName = storeNameResult[0]?.name;

      const userNameQuery = 'SELECT name FROM usersignin WHERE idusersignin = ?';
      connection.query(userNameQuery, [userId], (userNameErr, userNameResult) => {
        if (userNameErr) {
          console.error('Error querying userName:', userNameErr);
          return res.status(500).send('Error querying userName');
        }

        const userName = userNameResult[0]?.name;

        res.render('userorderdetails', {
          orderDetails: results,
          orderId: orderId,
          storeName: storeName,  
          userName: userName,    
          storeId: storeId,
          userId: userId,      
        });
      });
    });
  });
});




app.get('/storeinfo', (req, res) => {
  const storeId = req.session.storeId;
  const userId = req.session.userId;

  if (!storeId || !userId) {
    return res.status(400).send('Store ID or User ID is missing');
  }

  const storeSql = `
    SELECT 
      storesignin.name AS storeName, 
      storesignin.contactname, 
      storesignin.place, 
      storesignin.mobilenumber, 
      usersignin.name AS userName, 
      usersignin.idusersignin AS userId
    FROM 
      storesignin
    LEFT JOIN 
      usersignin 
    ON 
      storesignin.storepincode = usersignin.pincode
    WHERE 
      storesignin.storeid = ?`;

  connection.query(storeSql, [storeId], (err, storeResult) => {
    if (err) {
      console.error('Error fetching store information:', err);
      res.status(500).send('Server error');
      return;
    }

    if (storeResult.length > 0) {
      const { storeName, contactname, place, mobilenumber, userName } = storeResult[0];

      res.render('storeinfo', {
        storeName,
        storesignin: { contactname, place, mobilenumber },
        userName,
        storeId, 
        userId   
      });
    } else {
      res.status(404).send('Store not found');
    }
  });
});


app.get('/editprofile', (req, res) => {
  const idusersignin = req.session.userId;
  const storeId = req.session.storeId;

  if (!idusersignin || !storeId) {
    return res.status(400).send('User ID or Store ID is missing');
  }

  const query = `
    SELECT 
      usersignin.name AS userName,
      storesignin.name AS storeName,
      usersignin.*, 
      usersignin.mobilenumber AS mobilenumber
    FROM 
      usersignin
    JOIN 
      storesignin 
    ON 
      storesignin.storeid = ?
    WHERE 
      usersignin.idusersignin = ?`;

  connection.query(query, [storeId, idusersignin], (error, results) => {
    if (error) {
      console.error('Error fetching user details:', error);
      res.send('Error fetching user details');
    } else {
      if (results.length > 0) {
        res.render('editprofile', { 
          user: results[0],
          storeName: results[0].storeName,
          userName: results[0].userName,
          storeId, 
          userId: idusersignin 
        });
      } else {
        res.send('User not found');
      }
    }
  });
});


//store****



app.get('/storedetails/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  req.session.storeId = storeId;

  const currentPage = parseInt(req.query.page) || 1;
  const itemsPerPage = 25;
  const sortKey = req.query.sortKey || 'productname';
  const sortOrder = req.query.sortOrder || 'asc';
  
  const searchQuery = req.query.search || '';

  const storeQuery = 'SELECT storeid, name, contactname FROM storesignin WHERE storeid = ?';

  connection.query(storeQuery, [storeId], (error, storeResults) => {
    if (error) {
      console.error('Error fetching store:', error);
      return res.status(500).send('Internal Server Error');
    }

    if (storeResults.length > 0) {
      const storeData = storeResults[0];
      const { storeid, name, contactname } = storeData;

      let productsQuery = `
        SELECT p.productid, p.productname, p.category, p.code, p.hsn, p.salesprice, p.GST, p.description,
               IFNULL(s.storeproductid, 0) AS storeproductid, IFNULL(s.qty, 0) AS qty
        FROM products AS p
        LEFT JOIN storeproducts AS s ON p.productid = s.productid AND s.storeid = ?
        WHERE p.producttype != 'productfamily'`;

      if (searchQuery) {
        productsQuery += ` AND p.productname LIKE ?`;
      }
      if (sortKey === 'productname') {
        productsQuery += ` ORDER BY p.productname ${sortOrder}`;
      } else if (sortKey === 'qty') {
        productsQuery += ` ORDER BY s.qty ${sortOrder}`;
      } else if (sortKey === 'salesprice') {
        productsQuery += ` ORDER BY p.salesprice ${sortOrder}`;
      } else if (sortKey === 'category') {
        productsQuery += ` ORDER BY p.category ${sortOrder}`;
      } else {
        productsQuery += ' ORDER BY p.productname ASC'; 
      }
      

      connection.query(productsQuery, [storeId, `%${searchQuery}%`], (error, productsResults) => {
        if (error) {
          console.error('Error fetching products:', error);
          return res.status(500).send('Internal Server Error');
        }

        const products = productsResults;
        const totalProducts = products.length;
        const totalStockValue = products.reduce((total, product) => total + (product.qty * product.salesprice), 0);

        const productIdsToInsert = products
          .filter(product => product.storeproductid === 0)
          .map(product => product.productid);

        if (productIdsToInsert.length > 0) {
          const insertQuery = 'INSERT INTO storeproducts (storeid, productid, qty) VALUES (?, ?, 0)';
          productIdsToInsert.forEach(productId => {
            connection.query(insertQuery, [storeId, productId], (error) => {
              if (error) {
                console.error('Error inserting product into storeproducts:', error);
              }
            });
          });
        }

        const productIds = products.map(product => product.productid);
        let images = [];

        if (productIds.length > 0) {
          const imageQuery = `SELECT imagepath, productid FROM productimages WHERE productid IN (?)`;
          connection.query(imageQuery, [productIds], (error, imageResults) => {
            if (error) {
              console.error('Error fetching images:', error);
              return res.status(500).send('Internal Server Error');
            }

            images = imageResults.map(image => ({
              imagepath: image.imagepath ? `data:image/jpeg;base64,${image.imagepath}` : '',
              productid: image.productid,
            }));

            renderPage(products, images);
          });
        } else {
          renderPage(products, images);
        }

        function renderPage(products, images) {
          const startIndex = (currentPage - 1) * itemsPerPage;
          const endIndex = startIndex + itemsPerPage;
          const paginatedProducts = products.slice(startIndex, endIndex);
          const totalPages = Math.ceil(products.length / itemsPerPage);

          res.render('storedetails', {
            storeId,
            name,
            contactname,
            products: paginatedProducts,
            images,
            currentPage,
            totalPages,
            totalProducts,
            totalStockValue,
            sortKey,
            sortOrder,
            itemsPerPage,
            searchQuery 
          });
        }
      });
    } else {
      return res.render('storedetails', {
        storeId,
        name: '',
        contactname: '',
        products: [],
        images: [],
        currentPage: 1,
        totalPages: 1,
        totalProducts: 0,
        totalStockValue: 0,
        sortKey,
        sortOrder,
        itemsPerPage,
        searchQuery 
      });
    }
  });
});




app.get('/addSpecialOfferForm/:storeid', (req, res) => {
  const storeId = req.params.storeid;

  const storeDetailsQuery = 'SELECT name, contactname FROM storesignin WHERE storeid = ?';

  const specialOffersQuery = 'SELECT * FROM specialoffers WHERE storeid = ?';

  const storeProductsQuery = 'SELECT productid FROM storeproducts WHERE storeid = ?';

  connection.query(storeDetailsQuery, [storeId], (err, storeResult) => {
    if (err) {
      console.error('Error fetching store details:', err);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (storeResult.length === 0) {
      res.status(404).send('Store not found');
      return;
    }

    const name = storeResult[0].name;
    const contactname = storeResult[0].contactname;

    connection.query(specialOffersQuery, [storeId], (err, specialOffersResult) => {
      if (err) {
        console.error('Error fetching special offers:', err);
        res.status(500).send('Internal Server Error');
        return;
      }

      connection.query(storeProductsQuery, [storeId], (err, storeProductsResult) => {
        if (err) {
          console.error('Error fetching store products:', err);
          res.status(500).send('Internal Server Error');
          return;
        }

        const productIds = storeProductsResult.map(product => product.productid);

        if (productIds.length === 0) {
          res.render('specialoffer', {
            storeId: storeId,
            name: name,
            contactname: contactname,
            specialOffers: specialOffersResult,
            products: [] 
          });
          return;
        }

        const productsQuery = 'SELECT productid, productname FROM products WHERE productid IN (?)';

        connection.query(productsQuery, [productIds], (err, productsResult) => {
          if (err) {
            console.error('Error fetching products:', err);
            res.status(500).send('Internal Server Error');
            return;
          }

          res.render('specialoffer', {
            storeId: storeId,
            name: name,
            contactname: contactname,
            specialOffers: specialOffersResult,
            products: productsResult 
          });
        });
      });
    });
  });
});



app.post('/uploadOffer', (req, res) => {
  console.log(req.body);

  let { storeId, productId, content, expiryDate, discountPrice } = req.body;

  if (!productId) {
    res.status(400).json({ message: 'Product ID is required' });
    return;
  }

  const selectExpiredSql = 'SELECT offerid FROM specialoffers WHERE storeid = ? AND expirydate < CURRENT_TIMESTAMP';
  connection.query(selectExpiredSql, [storeId], (selectErr, expiredOffers) => {
    if (selectErr) {
      console.error('Error selecting expired special offers:', selectErr);
      res.status(500).json({ message: 'Internal Server Error' });
      return;
    }

    const expiredOfferIds = expiredOffers.map(offer => offer.offerid);

    if (expiredOfferIds.length > 0) {
      const deleteSpecialOffersSql = 'DELETE FROM specialoffers WHERE offerid IN (?)';
      connection.query(deleteSpecialOffersSql, [expiredOfferIds], (deleteSpecialOffersErr) => {
        if (deleteSpecialOffersErr) {
          console.error('Error deleting expired special offers:', deleteSpecialOffersErr);
          res.status(500).json({ message: 'Internal Server Error' });
          return;
        }

        const deleteStoreProductsSql = 'UPDATE storeproducts SET offerid = NULL WHERE offerid IN (?)';
        connection.query(deleteStoreProductsSql, [expiredOfferIds], (deleteStoreProductsErr) => {
          if (deleteStoreProductsErr) {
            console.error('Error updating store products to remove expired offer IDs:', deleteStoreProductsErr);
            res.status(500).json({ message: 'Internal Server Error' });
            return;
          }

          insertOrUpdateSpecialOffer();
        });
      });
    } else {
      insertOrUpdateSpecialOffer();
    }
  });

  function insertOrUpdateSpecialOffer() {
    const insertSql = `INSERT INTO specialoffers (storeid, productid, content, discountprice, expirydate) 
                       VALUES (?, ?, ?, ?, ?)
                       ON DUPLICATE KEY UPDATE content = VALUES(content), 
                                               discountprice = VALUES(discountprice), 
                                               expirydate = VALUES(expirydate)`;
    connection.query(insertSql, [storeId, productId, content, discountPrice, expiryDate], (insertErr, insertResult) => {
      if (insertErr) {
        console.error('Error inserting or updating store product offer:', insertErr);
        res.status(500).json({ message: 'Internal Server Error' });
      } else {
        const offerId = insertResult.insertId || null;

        const updateStoreProductsSql = `UPDATE storeproducts SET offerid = ? WHERE storeid = ? AND productid = ?`;
        connection.query(updateStoreProductsSql, [offerId, storeId, productId], (updateErr) => {
          if (updateErr) {
            console.error('Error updating store product with offer ID:', updateErr);
            res.status(500).json({ message: 'Internal Server Error' });
          } else {
            res.json({ message: 'Offer added successfully' });
          }
        });
      }
    });
  }
});

app.get('/editOffer/:offerid', (req, res) => {
  const offerId = req.params.offerid;

  const offerDetailsQuery = `
    SELECT si.storeid, si.name, si.contactname, so.*
    FROM storesignin si
    JOIN specialoffers so ON so.storeid = si.storeid
    WHERE so.offerid = ?`;

  connection.query(offerDetailsQuery, [offerId], (err, result) => {
    if (err) {
      console.error('Error fetching special offer details:', err);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (result.length === 0) {
      res.status(404).send('Offer details updated successfully');
      return;
    }

    const offer = result[0];
    const storeId = offer.storeid;
    const name = offer.name;
    const contactname = offer.contactname;

    res.render('editOffer', {
      offerId: offerId,
      storeId: storeId, 
      name: name,
      contactname: contactname,
      offer: offer 
    });
  });
});


app.post('/updateOffer1/:offerid', (req, res) => {
  const offerId = req.params.offerid;
  const { productId, content, discountPrice, expiryDate } = req.body;

  const sql = `
    UPDATE specialoffers 
    SET productid = ?, content = ?, discountprice = ?, expirydate = ?
    WHERE offerid = ?
  `;

  connection.query(sql, [productId, content, discountPrice, expiryDate, offerId], (err, result) => {
    if (err) {
      console.error('Error updating special offer:', err);
      res.status(500).send('Internal Server Error');
      return;
    }

    res.json({ message: 'Offer details updated successfully' });
  });
});


app.delete('/deleteOffer/:offerid', (req, res) => {
  const offerId = req.params.offerid;

  connection.beginTransaction((transactionErr) => {
    if (transactionErr) {
      console.error('Error starting transaction:', transactionErr);
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }

  
    const deleteOfferSql = 'DELETE FROM specialoffers WHERE offerid = ?';
    connection.query(deleteOfferSql, [offerId], (deleteOfferErr, deleteOfferResult) => {
      if (deleteOfferErr) {
        console.error('Error deleting special offer:', deleteOfferErr);
        return connection.rollback(() => {
          res.status(500).json({ error: 'Internal Server Error' });
        });
      }

      
      const updateStoreProductSql = 'UPDATE storeproducts SET offerid = NULL WHERE offerid = ?';
      connection.query(updateStoreProductSql, [offerId], (updateStoreProductErr, updateStoreProductResult) => {
        if (updateStoreProductErr) {
          console.error('Error updating storeproducts:', updateStoreProductErr);
          return connection.rollback(() => {
            res.status(500).json({ error: 'Internal Server Error' });
          });
        }

        connection.commit((commitErr) => {
          if (commitErr) {
            console.error('Error committing transaction:', commitErr);
            return connection.rollback(() => {
              res.status(500).json({ error: 'Internal Server Error' });
            });
          }

          res.json({ success: true, message: 'Offer deleted successfully and offerid updated to NULL in storeproducts' });
        });
      });
    });
  });
});
app.get('/getSpecialOffer/:storeId', (req, res) => {
  const storeId = req.params.storeId;
  const currentDate = new Date().toISOString().split('T')[0];

  const sql = 'SELECT * FROM specialoffers WHERE storeid = ? AND expirydate >= ? ORDER BY expirydate ASC LIMIT 1';
  connection.query(sql, [storeId, currentDate], (err, result) => {
    if (err) {
      console.error('Error fetching special offer:', err);
      res.status(500).json({ error: 'Internal Server Error' });
    } else {
      if (result.length > 0) {
        res.render('specialoffer', { specialOffer: result[0] });
      } else {
        res.render('specialoffer', { specialOffer: null });
      }
    }
  });
});

app.get('/addproduct/:storeid', (req, res) => {
  const storeId = req.params.storeid;

  const storeQuery = 'SELECT name, contactname FROM storesignin WHERE storeid = ?';

  connection.query(storeQuery, [storeId], (error, storeResults) => {
    if (error) {
      console.error('Error fetching store details:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (storeResults.length > 0) {
      const name = storeResults[0].name;
      const contactname = storeResults[0].contactname;

      const productsQuery = 'SELECT * FROM products WHERE qty > 0';
      const storeProductsQuery = 'SELECT productid FROM storeproducts WHERE storeid = ?';

      connection.query(productsQuery, (error, products) => {
        if (error) {
          console.error('Error fetching products:', error);
          res.status(500).send('Internal Server Error');
          return;
        }

        connection.query(storeProductsQuery, [storeId], (error, storeProducts) => {
          if (error) {
            console.error('Error fetching store products:', error);
            res.status(500).send('Internal Server Error');
            return;
          }

          const availableProductIds = storeProducts.map(p => p.productid);

          console.log('Available Product IDs:', availableProductIds);

          res.render('addproduct', { storeId, name, contactname, products, availableProductIds });
        });
      });
    } else {
      res.status(404).send('Store not found');
    }
  });
});


app.post('/addselectedproducts/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  const selectedProducts = req.body.products; 
  console.log('Received request to update products:', selectedProducts); 

  if (!Array.isArray(selectedProducts) || selectedProducts.length === 0) {
      const errorMessage = 'No products selected.';
      console.error(errorMessage);
      return res.status(400).send(errorMessage);
  }

  console.log('Selected Products Data:', selectedProducts);

  connection.beginTransaction((transactionErr) => {
      if (transactionErr) {
          const errorMessage = `Error starting transaction: ${transactionErr.message}`;
          console.error(errorMessage);
          return res.status(500).send(errorMessage);
      }

      const updatePromises = selectedProducts.map(product => {
          return new Promise((resolve, reject) => {
              const { productId, quantity } = product;

              const checkStoreProductQuery = 'SELECT storeproductid, qty FROM storeproducts WHERE storeid = ? AND productid = ?';
              connection.query(checkStoreProductQuery, [storeId, productId], (checkStoreProductError, checkStoreProductResults) => {
                  if (checkStoreProductError) {
                      const errorMessage = `Error checking store product: ${checkStoreProductError.message}`;
                      console.error(errorMessage);
                      return reject(errorMessage);
                  }

                  if (checkStoreProductResults.length > 0) {
                      const updateStoreProductQuery = 'UPDATE storeproducts SET qty = qty + ? WHERE storeid = ? AND productid = ?';
                      connection.query(updateStoreProductQuery, [quantity, storeId, productId], (updateStoreProductError) => {
                          if (updateStoreProductError) {
                              const errorMessage = `Error updating store product: ${updateStoreProductError.message}`;
                              console.error(errorMessage);
                              return reject(errorMessage);
                          }

                          const updateProductQtyQuery = 'UPDATE products SET qty = qty - ? WHERE productid = ?';
                          connection.query(updateProductQtyQuery, [quantity, productId], (updateProductQtyError) => {
                              if (updateProductQtyError) {
                                  const errorMessage = `Error updating main product qty: ${updateProductQtyError.message}`;
                                  console.error(errorMessage);
                                  return reject(errorMessage);
                              }
                              resolve();
                          });
                      });
                  } else {
                      const insertStoreProductQuery = 'INSERT INTO storeproducts (storeid, productid, qty) VALUES (?, ?, ?)';
                      connection.query(insertStoreProductQuery, [storeId, productId, quantity], (insertStoreProductError) => {
                          if (insertStoreProductError) {
                              const errorMessage = `Error inserting new store product: ${insertStoreProductError.message}`;
                              console.error(errorMessage);
                              return reject(errorMessage);
                          }
                          const updateProductQtyQuery = 'UPDATE products SET qty = qty - ? WHERE productid = ?';
                          connection.query(updateProductQtyQuery, [quantity, productId], (updateProductQtyError) => {
                              if (updateProductQtyError) {
                                  const errorMessage = `Error updating main product qty: ${updateProductQtyError.message}`;
                                  console.error(errorMessage);
                                  return reject(errorMessage);
                              }
                              resolve();
                          });
                      });
                  }
              });
          });
      });

      Promise.all(updatePromises)
          .then(() => {
              connection.commit((commitErr) => {
                  if (commitErr) {
                      const errorMessage = `Error committing transaction: ${commitErr.message}`;
                      console.error(errorMessage);
                      connection.rollback(() => {
                          res.status(500).send(errorMessage);
                      });
                  } else {
                      res.status(200).send('Update successful');
                  }
              });
          })
          .catch((error) => {
              console.error('Transaction error: ', error);
              connection.rollback(() => {
                  res.status(500).send(error);
              });
          });
  });
});


app.get('/storeuserdetails/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  const currentPage = parseInt(req.query.page) || 1; 
  const itemsPerPage = 25; 

  const storeQuery = 'SELECT name, contactname, storepincode FROM storesignin WHERE storeid = ?';

  connection.query(storeQuery, [storeId], (error, storeResults) => {
    if (error) {
      console.error('Error fetching store details:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (storeResults.length > 0) {
      const name = storeResults[0].name;
      const contactname = storeResults[0].contactname;
      const storePincode = storeResults[0].storepincode;

      const query = `
        SELECT u.*, s.name AS storeName, s.place AS storePlace
        FROM usersignin u
        LEFT JOIN storesignin s ON FIND_IN_SET(u.pincode, s.storepincode) > 0
        WHERE s.storeid = ?
        LIMIT ? OFFSET ?;
      `;

      const offset = (currentPage - 1) * itemsPerPage;

      connection.query(query, [storeId, itemsPerPage, offset], (error, results) => {
        if (error) {
          console.error('Error fetching users:', error);
          res.status(500).send('Internal Server Error');
          return;
        }
        res.render('storeuserdetails', {
          storeId,
          name,
          contactname,
          users: results,
          currentPage,
          totalPages: Math.ceil(results.length / itemsPerPage),
          itemsPerPage 
        });
      });
    } else {
      res.status(404).send('Store not found');
    }
  });
});


let orders = [];

app.get('/storeorder/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  const { status, fromDate, toDate } = req.query;

  const checkStoreQuery = `
    SELECT 
      COUNT(DISTINCT orderid) AS totalOrdersCount,
      COUNT(DISTINCT CASE WHEN overallstatus != 'delivered' THEN orderid END) AS openOrdersCount
    FROM \`order\`
    WHERE storeid = ?
  `;

  connection.query(checkStoreQuery, [storeId], (checkStoreError, checkStoreResults) => {
    if (checkStoreError) {
      console.error('Error checking storeId:', checkStoreError);
      return res.status(500).send('Internal Server Error');
    }

    const totalOrdersCount = checkStoreResults[0].totalOrdersCount;
    const openOrdersCount = checkStoreResults[0].openOrdersCount;

    if (totalOrdersCount === 0) {
      return res.render('storeorder', {
        storeName: null,
        contactName: null,
        orders: null,
        storeId,
        noOrdersFound: true,
        totalOrdersCount: 0,
        openOrdersCount: 0,
      });
    }

    let orderQuery = `
      SELECT orderid, userid, productid, productname, price, quantity, orderdate, totalprice, status, overallstatus
      FROM \`order\`
      WHERE storeid = ?
    `;

    const queryParams = [storeId];

    if (status) {
      orderQuery += ' AND overallstatus = ?';
      queryParams.push(status);
    }

    if (fromDate && toDate) {
      orderQuery += ' AND DATE(orderdate) BETWEEN ? AND ?';
      queryParams.push(fromDate, toDate);
    } else if (fromDate) {
      orderQuery += ' AND DATE(orderdate) >= ?';
      queryParams.push(fromDate);
    } else if (toDate) {
      orderQuery += ' AND DATE(orderdate) <= ?';
      queryParams.push(toDate);
    }
    
    
    connection.query(orderQuery, queryParams, (error, orderResults) => {
      if (error) {
        console.error('Error retrieving orders:', error);
        return res.status(500).send('Internal Server Error');
      }

      const userIds = orderResults.map(order => order.userid);
      const userQuery = `
        SELECT idusersignin AS userId, name, mobilenumber, address
        FROM usersignin
        WHERE idusersignin IN (?)
      `;

      connection.query(userQuery, [userIds], (error, userResults) => {
        if (error) {
          console.error('Error retrieving user details:', error);
          return res.status(500).send('Internal Server Error');
        }

        const users = userResults;
        const userMap = {};
        users.forEach(user => {
          userMap[user.userId] = user;
        });

        orderResults.forEach(order => {
          order.userDetails = userMap[order.userid];
        
          const orderDate = new Date(order.orderdate);
          order.formattedOrderDate = orderDate.toLocaleString('en-GB', {
            day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'
          }).replace(',', '');  
        });
        
        

        const totalOrderedItems = orderResults.reduce((total, order) => total + order.quantity, 0);

        const storeInfoQuery = `
          SELECT name AS storeName, contactname
          FROM storesignin
          WHERE storeid = ?
        `;

        connection.query(storeInfoQuery, [storeId], (error, storeInfo) => {
          if (error) {
            console.error('Error retrieving store information:', error);
            return res.status(500).send('Internal Server Error');
          }

          const storeData = storeInfo[0];

          res.render('storeorder', {
            storeName: storeData.storeName,
            contactName: storeData.contactname,
            orders: orderResults,
            storeId,
            noOrdersFound: orderResults.length === 0,
            totalOrdersCount,
            totalOrderedItems,
            openOrdersCount,
          });
        });
      });
    });
  });
});


app.get('/storeorderdetails/:orderid', (req, res) => {
  let orderId = req.params.orderid.padStart(4, '0');
  const storeId = req.session.storeId;
  console.log('storeid for check:', storeId);

  console.log('orderId:', orderId); 
  console.log('storeId:', storeId); 
  const productsQuery = `
    SELECT productid, productname, price, quantity, orderdate, totalprice, status, overallstatus, userid
    FROM \`order\`
    WHERE orderid = ? AND storeid = ?
  `;

  connection.query(productsQuery, [orderId, storeId], (error, productsResults) => {
    if (error) {
      console.error('Error retrieving products details:', error);
      return res.status(500).send('Internal Server Error');
    }

    if (productsResults.length === 0) {
      return res.status(404).send('Order not found');
    }

    const products = productsResults; 

    const userId = products[0].userid;

    console.log('userId:', userId); 

    const userQuery = `
      SELECT idusersignin, name, mobilenumber, address
      FROM usersignin
      WHERE idusersignin = ?
    `;

    connection.query(userQuery, [userId], (userError, userResult) => {
      if (userError) {
        console.error('Error retrieving user details:', userError);
        return res.status(500).send('Internal Server Error');
      }

      const user = userResult[0]; 

      console.log('user:', user); 

      const storeInfoQuery = `
        SELECT name AS storeName, contactname
        FROM storesignin
        WHERE storeid = ?
      `;

      connection.query(storeInfoQuery, [storeId], (storeError, storeInfo) => {
        if (storeError) {
          console.error('Error retrieving store information:', storeError);
          return res.status(500).send('Internal Server Error');
        }

        const storeData = storeInfo[0]; 

        console.log('storeData:', storeData); 

        res.render('storeorderdetails', {
          products,
          overallStatus: products[0].overallstatus,
          orderId,
          user,
          name: storeData ? storeData.storeName : '', 
          contactname: storeData ? storeData.contactname : '',
          storeData,
          storeId, 
        });
      });
    });
  });
});

app.post('/updateOrderStatus/:orderid/:productid?', (req, res) => {
  const orderId = req.params.orderid;
  const productId = req.params.productid || null;
  const newStatus = req.body.status; 

  console.log('Updating order status for Order ID:', orderId, 'and Product ID:', productId);
  console.log('Request Body:', req.body);

  const updateStatusQuery = `
      UPDATE \`order\`
      SET status = ?
      WHERE orderid = ? ${productId ? 'AND productid = ?' : ''}`;
  
  const params = [newStatus, orderId];
  if (productId) {
      params.push(productId);
  }

  connection.query(updateStatusQuery, params, (error, result) => {
      if (error) {
          console.error('Error updating order status:', error);
          return res.status(500).send('Internal Server Error');
      }

      const orderQuery = `
          SELECT orderid, userid, productid, productname, price, quantity, orderdate, totalprice, status
          FROM \`order\`
          WHERE orderid = ? ${productId ? 'AND productid = ?' : ''}`;

      const orderParams = [orderId];
      if (productId) {
          orderParams.push(productId);
      }

      connection.query(orderQuery, orderParams, (error, updatedOrderResults) => {
          if (error) {
              console.error('Error retrieving updated order details:', error);
              return res.status(500).send('Internal Server Error');
          }

          const updatedOrder = updatedOrderResults[0]; 

          res.redirect(`/storeorderdetails/${orderId}`);
      });
  });
});

app.post('/updateOverallStatus/:orderid', (req, res) => {
  const orderId = req.params.orderid;
  const newOverallStatus = req.body.overallStatus;
  const storeId = req.session.storeId;

  console.log('Updating overall status for Order ID:', orderId);
  console.log('New Overall Status:', newOverallStatus);
  console.log('Store ID:', storeId); 

  const updateOverallStatusQuery = `
      UPDATE \`order\`
      SET overallstatus = ?
      WHERE orderid = ?`;

  connection.query(updateOverallStatusQuery, [newOverallStatus, orderId], (error, result) => {
      if (error) {
          console.error('Error updating overall status:', error);
          return res.status(500).send('Internal Server Error');
      }

      console.log('Redirecting to storeorderdetails page...');
      res.redirect(`/storeorder/${storeId}`);
  });
});



app.get('/editstore/:storeid', (req, res) => {
  const storeId = req.params.storeid;

  const storeQuery = 'SELECT * FROM storesignin WHERE storeid = ?';
  connection.query(storeQuery, [storeId], (storeError, storeResults) => {
    if (storeError) {
      console.error('Error fetching store details:', storeError);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (storeResults.length > 0) {
      const store = storeResults[0];
      
      const name = store.name;
      const contactname = store.contactname;

      res.render('editstore', { store, storeId, name, contactname });

    } else {
      res.status(404).send('Store not found');
    }
  });
});

app.post('/updatestore1/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  const { name, contactname, place, gstnumber, mobilenumber, storepincode, password } = req.body;

  const query = 'UPDATE storesignin SET name = ?, contactname = ?, place = ?, gstnumber = ?, mobilenumber = ?, storepincode = ? WHERE storeid = ?';

  connection.query(query, [name, contactname, place, gstnumber, mobilenumber, storepincode, storeId], (error, results) => {
    if (error) {
      console.error('Error updating store details:', error);
      return res.status(500).json({ success: false, message: 'Failed to update store details. Please try again.' });
    }

    console.log('Store details updated successfully');
    res.json({ success: true, message: 'Store details updated successfully!' });
  });
});


app.get('/editproduct/:storeId/:productId', (req, res) => {
  const storeId = req.params.storeId;
  const productId = req.params.productId;

  const productQuery = 'SELECT * FROM products WHERE storeid = ? AND productid = ?';
  connection.query(productQuery, [storeId, productId], (error, productResults) => {
    if (error) {
      console.error('Error fetching product details:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (productResults.length > 0) {
      const product = productResults[0];

      const imageQuery = 'SELECT * FROM images WHERE productid = ?';
      connection.query(imageQuery, [productId], (error, imageResults) => {
        if (error) {
          console.error('Error fetching images:', error);
          res.status(500).send('Internal Server Error');
          return;
        }

        const images = imageResults;

        const storeNameQuery = 'SELECT name FROM storesignin WHERE storeid = ?';
        connection.query(storeNameQuery, [storeId], (error, storeNameResults) => {
          if (error) {
            console.error('Error fetching store name:', error);
            res.status(500).send('Internal Server Error');
            return;
          }

          if (storeNameResults.length > 0) {
            const storeName = storeNameResults[0].name;

            res.render('editproduct', { storeId, name: storeName, product, images });
          } else {
            res.status(404).send('Store not found');
          }
        });
      });
    } else {
      res.status(404).send('Product not found');
    }
  });
});

app.post('/updateproduct/:storeId/:productId', (req, res) => {
  const storeId = req.params.storeId;
  const productId = req.params.productId;
  const updatedProduct = req.body;

  const updateQuery =
    'UPDATE products SET productname = ?, category = ?, code = ?, hsn = ?, salesprice = ?, mrp = ?, qty = ?, description = ? WHERE storeid = ? AND productid = ?';
  connection.query(
    updateQuery,
    [
      updatedProduct.productName,
      updatedProduct.category,
      updatedProduct.code,
      updatedProduct.hsn,
      updatedProduct.salesPrice,
      updatedProduct.mrp,
      updatedProduct.qty,
      updatedProduct.description,
      storeId,
      productId
    ],
    (error, result) => {
      if (error) {
        console.error('Error updating product details:', error);
        res.status(500).send('Internal Server Error');
        return;
      }

      if (req.files && req.files.newImages) {
        const newImages = Array.isArray(req.files.newImages) ? req.files.newImages : [req.files.newImages];

        const deleteImagesQuery = 'DELETE FROM images WHERE productid = ?';
        connection.query(deleteImagesQuery, [productId], (error) => {
          if (error) {
            console.error('Error deleting old images:', error);
            res.status(500).send('Internal Server Error');
            return;
          }

          newImages.forEach((image) => {
            const imagePath = '/images/' + image.name;
            image.mv('public' + imagePath, (error) => {
              if (error) {
                console.error('Error saving image:', error);
              } else {
                const insertImageQuery = 'INSERT INTO images (imagepath, productid) VALUES (?, ?)';
                connection.query(insertImageQuery, [imagePath, productId], (error) => {
                  if (error) {
                    console.error('Error inserting image:', error);
                  }
                });
              }
            });
          });
          res.redirect(`/storedetails/${storeId}`); 
        });
      } else {
        res.redirect(`/storedetails/${storeId}`); 
      }
    }
  );
});

app.get('/replaceimage/:productid/:imageid', (req, res) => {
  const productId = req.params.productid;
  const imageId = req.params.imageid;

  const getImagePathQuery = 'SELECT imagepath FROM images WHERE productid = ? AND imageid = ?';
  connection.query(getImagePathQuery, [productId, imageId], (error, result) => {
    if (error) {
      console.error('Error fetching image path:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (result.length === 0) {
      res.status(404).send('Image not found');
      return;
    }

    const existingImagePath = result[0].imagepath;

    res.render('replaceimage', { productId, imageId, existingImagePath });
  });
});

app.post('/replaceimage/:productid/:imageid', uploadDisk.single('newImage'), (req, res) => {
  const productId = req.params.productid;
  const imageId = req.params.imageid;

 
  if (!req.file) {
    return res.status(400).send('No image file selected');
  }

  const getImagePathQuery = 'SELECT imagepath FROM images WHERE productid = ? AND imageid = ?';
  connection.query(getImagePathQuery, [productId, imageId], (error, result) => {
    if (error) {
      console.error('Error fetching image path:', error);
      return res.status(500).send('Internal Server Error');
    }

    if (result.length === 0) {
      return res.status(404).send('Image not found');
    }

    const existingImagePath = result[0].imagepath;

    if (fs.existsSync(existingImagePath)) {
      fs.unlink(existingImagePath, (unlinkError) => {
        if (unlinkError) {
          console.error('Error deleting existing image:', unlinkError);
          return res.status(500).send('Failed to delete existing image');
        }

     
        const newImagePath = path.join(__dirname, 'public', 'images', req.file.filename);

        fs.rename(req.file.path, newImagePath, (renameError) => {
          if (renameError) {
            console.error('Error saving new image:', renameError);
            return res.status(500).send('Failed to save new image');
          }

       
          const updateImageQuery =
            'UPDATE images SET imagepath = ?, imageid = ? WHERE productid = ? AND imageid = ?';
          connection.query(
            updateImageQuery,
            [newImagePath, req.file.filename, productId, imageId],
            (updateError) => {
              if (updateError) {
                console.error('Error updating image path in database:', updateError);
                return res.status(500).send('Failed to update database');
              }

              res.redirect(`/editproduct/${productId}`);
            }
          );
        });
      });
    } else {
      console.error('Existing image file not found:', existingImagePath);
      res.status(404).send('Existing image file not found');
    }
  });
});

app.get('/editstore/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  const connection = req.app.locals.connection;

  const sql = 'SELECT * FROM storesignin WHERE storeid = ?';
  connection.query(sql, [storeId], (err, results) => {
    if (err) {
      console.error('Error fetching store details:', err);
      res.status(500).json({ error: 'Failed to fetch store details. Please try again later.' });
    } else if (results.length === 0) {
      res.status(404).json({ error: 'Store not found.' });
    } else {
      const storeDetails = results[0];
      res.render('editstore', { storeDetails });
    }
  });
});


app.delete('/removeimage/:imageId', (req, res) => {
  const imageId = req.params.imageId;

  const deleteImageQuery = 'DELETE FROM images WHERE imageid = ?';
  connection.query(deleteImageQuery, [imageId], (error, results) => {
    if (error) {
      console.error('Error removing image:', error);
      res.status(500).send('Internal Server Error');
    } else {
      res.json({ success: true });
    }
  });
});


app.get('/update-stock/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  console.log("Received storeId:", storeId);

  if (!storeId) {
    console.error('Error: storeId is undefined or missing');
    return res.status(400).send('Bad Request: storeId is undefined or missing');
  }

  const storeQuery = 'SELECT storeid, name, contactname FROM storesignin WHERE storeid = ?';

  connection.query(storeQuery, [storeId], (error, storeResults) => {
    if (error) {
      console.error('Error fetching store:', error);
      return res.status(500).send('Internal Server Error');
    }

    if (storeResults.length > 0) {
      const name = storeResults[0].name;
      const contactname = storeResults[0].contactname;
      res.render('update-Stock', { storeId, name, contactname });
    } else {
      console.error('Store not found');
      res.status(404).send('Store not found');
    }
  });
});


app.post('/update-stock/upload', uploadDisk.single('excelFile'), (req, res) => {
  if (!req.file) {
    console.error('Error: No file uploaded');
    return res.status(400).send({ success: false, message: 'No file uploaded' });
  }

  console.log('File uploaded:', req.file); 

  const workbook = xlsx.readFile(req.file.path);
  const worksheet = workbook.Sheets[workbook.SheetNames[0]];
  const data = xlsx.utils.sheet_to_json(worksheet);

  const storeId = req.body.storeId;

  if (!storeId) {
    console.error('Error: storeId is undefined or missing');
    return res.status(400).send({ success: false, message: 'storeId is undefined or missing' });
  }

  console.log("Received storeId:", storeId);

  
  const updatePromises = data.map((row) => {
    return new Promise((resolve, reject) => {
      const { 'Product ID': productid, Qty: newQty } = row;

      console.log("Processing row:", row);

      const storeQuery = 'UPDATE storeproducts SET qty = qty + ? WHERE storeid = ? AND productid = ?';
      console.log("SQL Query for storeproducts:", storeQuery);
      console.log("Parameters for storeproducts:", [newQty, storeId, productid]);

      connection.query(storeQuery, [newQty, storeId, productid], (error, results) => {
        if (error) {
          console.error('Error updating storeproducts table:', error);
          return reject('Error updating storeproducts table');
        }
        console.log("Storeproducts update successful:", results);

        const productQuery = 'UPDATE products SET qty = qty - ? WHERE productid = ?';
        console.log("SQL Query for products:", productQuery);
        console.log("Parameters for products:", [newQty, productid]);

        connection.query(productQuery, [newQty, productid], (error, results) => {
          if (error) {
            console.error('Error updating products table:', error);
            return reject('Error updating products table');
          }
          console.log("Products update successful:", results);
          resolve(); 
        });
      });
    });
  });
  Promise.all(updatePromises)
    .then(() => {
      res.send({ success: true, message: 'Products quantity updated successfully' });
    })
    .catch((error) => {
      console.error('Error during update process:', error);
      res.status(500).send({ success: false, message: error });
    });
});


app.get('/download-products-excel', (req, res) => {
  const storeId = req.query.storeId;

  if (!storeId) {
    console.error('Error: storeId is undefined or missing');
    return res.status(400).send('Bad Request: storeId is undefined or missing');
  }

  const query = `
  SELECT p.productid, p.productname, p.category, p.code, p.hsn, p.salesprice, p.weight, 0 AS qty, p.GST
  FROM products p
  INNER JOIN storeproducts sp ON p.productid = sp.productid
  WHERE sp.storeid = ?`;

  connection.query(query, [storeId], (error, results) => {
    if (error) {
      console.error('Error fetching product details:', error);
      return res.status(500).send('Internal Server Error');
    }

    const workbook = new excel.Workbook();
    const worksheet = workbook.addWorksheet('Products');

    worksheet.columns = [
      { header: 'Product ID', key: 'productid', width: 15 },
      { header: 'Product Name', key: 'productname', width: 30 },
      { header: 'Category', key: 'category', width: 20 },
      { header: 'Code', key: 'code', width: 20 },
      { header: 'HSN', key: 'hsn', width: 15 },
      { header: 'Sales Price', key: 'salesprice', width: 15 },
      { header: 'Weight', key: 'weight', width: 15 },
      { header: 'Qty', key: 'qty', width: 10 },
      { header: 'GST', key: 'GST', width: 20 }
    ];

    results.forEach(product => {
      worksheet.addRow(product);
    });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=products.xlsx');

    workbook.xlsx.write(res)
      .then(() => {
        res.end();
      })
      .catch(err => {
        console.error('Error writing Excel file:', err);
        res.status(500).send('Internal Server Error');
      });
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});