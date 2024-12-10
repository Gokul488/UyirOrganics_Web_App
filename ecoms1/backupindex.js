const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const multer = require('multer');

const fs = require('fs');
const bodyParser = require('body-parser');
const twilio = require('twilio');
const bcrypt = require('bcrypt');

const session = require('express-session');





const saltRounds = 10; 


require('dotenv').config();




const app = express();
const port = 7777;



const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Gowshik@123',
  database: 'mytestdb',
});

connection.connect((error) => {
  if (error) {
    console.error('Error connecting to MySQL:', error);
  } else {
    console.log('Connected to MySQL database');
  }
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());



app.use(session({
  secret: '3V@8w*PqR2yZ$T4n&LmG5jCk',
  resave: false,
  saveUninitialized: true
}));

app.use(express.urlencoded({ extended: false }));
app.use('/images', express.static(path.join(__dirname, 'public', 'images')));
app.use(express.static('images'));
app.use(express.json());


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public', 'images'));
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({ storage });


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'FRONT.html'));
});




// admin ..........................................................



// Handle admin authentication

app.get('/adminstoredetails', (req, res) => {
  // Query the database to fetch store details in alphabetical order
  connection.query('SELECT * FROM storesignin ORDER BY name', (error, results) => {
    if (error) {
      console.error('Error fetching store details: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Query the database to get the total number of stores
    connection.query('SELECT COUNT(*) as storeCount FROM storesignin', (error, countResult) => {
      if (error) {
        console.error('Error fetching store count: ' + error);
        res.status(500).send('Internal Server Error');
        return;
      }

      // Render the "adminstoredetails.ejs" template with the fetched data and store count
      res.render('adminstoredetails', { storeDetails: results, storeCount: countResult[0].storeCount });
    });
  });
});


// Define a route for handling userdetails button click
app.get('/userdetails', (req, res) => {
  const storeId = req.query.storeid; // Assuming storeId is passed as a query parameter

  // Query the database to retrieve user details based on storeId's pincode range
  const sql = `
    SELECT u.*
    FROM usersignin u
    JOIN storesignin s ON u.pincode BETWEEN s.frompincode AND s.topincode
    WHERE s.storeid = ?
  `;

  connection.query(sql, [storeId], (err, results) => {
    if (err) {
      console.error(err);
      // You can handle errors here by sending an error response or rendering an error page
      res.status(500).send('Internal Server Error');
    } else {
      // Render a webpage to display user details
      res.render('userdetails', { userDetails: results });
    }
  });
});


app.get('/adminuserdetails', (req, res) => {
  const page = req.query.page || 1; // Get the page number from the query parameter, default to page 1
  const pageSize = 15; // Number of users per page

  // Calculate the OFFSET for pagination
  const offset = (page - 1) * pageSize;

  // Query to count the total number of users
  const countQuery = 'SELECT COUNT(*) AS totalUsersCount FROM usersignin';

  connection.query(countQuery, (countError, countResults) => {
    if (countError) {
      console.error('Error counting users: ' + countError);
      res.status(500).send('Internal Server Error');
      return;
    }

    const totalUsersCount = countResults[0].totalUsersCount;

    // Query the database to fetch user details along with name and place from storesignin table with pagination
    const query = `
      SELECT u.*, s.name AS storeName, s.place AS storePlace
      FROM usersignin u
      LEFT JOIN storesignin s ON u.pincode BETWEEN s.frompincode AND s.topincode
      LIMIT ? OFFSET ?;
    `;

    connection.query(query, [pageSize, offset], (error, results) => {
      if (error) {
        console.error('Error fetching user details: ' + error);
        res.status(500).send('Internal Server Error');
        return;
      }

      // Calculate the total number of pages
      const totalPages = Math.ceil(totalUsersCount / pageSize);

      // Render the "adminuserdetails.ejs" template with the fetched data, pagination information, and total user count
      res.render('adminuserdetails', {
        userDetails: results,
        totalPages: totalPages,
        currentPage: page,
        pageSize: pageSize,
        totalUsersCount: totalUsersCount
      });
    });
  });
});


app.post('/updateAccess', (req, res) => {
  const userId = req.body.userId;
  const access = req.body.access;

  // Update the "access" column in the usersignin table using idusersignin
  const updateQuery = 'UPDATE usersignin SET access = ? WHERE idusersignin = ?';

  connection.query(updateQuery, [access, userId], (error, results) => {
    if (error) {
      console.error('Error updating access: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Redirect back to the user details page after updating
    res.redirect('/adminuserdetails');
  });
});




// Handle GET request to edit store details
// Handle GET request to edit store details
app.get('/admineditstore/:storeid', (req, res) => {
  const storeId = req.params.storeid;

  // Query the database to fetch store details by storeId
  connection.query('SELECT * FROM storesignin WHERE storeId = ?', [storeId], (error, results) => {
    if (error) {
      console.error('Error fetching store details: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Check if a store with the provided storeId exists
    if (results.length === 0) {
      res.status(404).send('Store not found');
      return;
    }

    const store = results[0];

    // Decrypt the password from the database
    const storedPassword = store.password;

    // Render the "admineditstore.ejs" template with the fetched data and decrypted password
    res.render('admineditstore', { store, decryptedPassword: storedPassword });
  });
});

app.post('/admineditstore/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  const { name, contactname, place, gstnumber, mobilenumber, frompincode, topincode, newPassword } = req.body;

  // Hash the new password before updating it in the database
  bcrypt.hash(newPassword, saltRounds, (bcryptError, hashedPassword) => {
    if (bcryptError) {
      console.error('Error hashing new password:', bcryptError);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Update the store's details, including the password, in the database
    const updateQuery = 'UPDATE storesignin SET name = ?, contactname = ?, place = ?, gstnumber = ?, mobilenumber = ?, frompincode = ?, topincode = ?, password = ? WHERE storeId = ?';
    connection.query(updateQuery, [name, contactname, place, gstnumber, mobilenumber, frompincode, topincode, hashedPassword, storeId], (error, results) => {
      if (error) {
        console.error('Error updating store details: ' + error);
        res.status(500).send('Internal Server Error');
        return;
      }

      // Redirect to a success page or perform other actions as needed
      res.redirect('/adminstoredetails');
    });
  });
});

app.get('/confirmdeletestore/:storeid', (req, res) => {
  const storeId = req.params.storeid;

  // Fetch store details for confirmation
  connection.query('SELECT * FROM storesignin WHERE storeId = ?', [storeId], (error, results) => {
    if (error) {
      console.error('Error fetching store details: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    const store = results[0];

    // Check if the store exists before rendering the confirmation page
    if (!store) {
      res.status(404).send('Store not found');
      return;
    }

    // Render the confirmation page with the store details
    res.render('admindeleteconfirm', { store: store, storeId: storeId });
  });
});



// Handle GET request to delete store details
app.get('/deletestore/:storeid', (req, res) => {
  const storeId = req.params.storeid;

  // Step 1: Remove cart items associated with the products
  connection.query('SELECT productid FROM products WHERE storeId = ?', [storeId], (error, products) => {
    if (error) {
      console.error('Error fetching products: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Get an array of product IDs
    const productIds = products.map((product) => product.productid);

    if (productIds.length === 0) {
      // No products associated with the store, no need to delete cart items
      continueDeletion();
    } else {
      // Delete cart items where productid is in the array of product IDs
      const deleteCartItemsQuery = 'DELETE FROM cart WHERE productid IN (?)';
      connection.query(deleteCartItemsQuery, [productIds], (error) => {
        if (error) {
          console.error('Error removing cart items: ' + error);
          res.status(500).send('Internal Server Error');
          return;
        }

        // Continue with the rest of the deletion process
        continueDeletion();
      });
    }

    function continueDeletion() {
      // Step 2: Delete products associated with the store
      connection.query('DELETE FROM products WHERE storeId = ?', [storeId], (error) => {
        if (error) {
          console.error('Error deleting products: ' + error);
          res.status(500).send('Internal Server Error');
          return;
        }

        // Step 3: Fetch store details for confirmation
        connection.query('SELECT * FROM storesignin WHERE storeId = ?', [storeId], (error, results) => {
          if (error) {
            console.error('Error fetching store details: ' + error);
            res.status(500).send('Internal Server Error');
            return;
          }

          const store = results[0];

          // Step 4: Delete the store
          connection.query('DELETE FROM storesignin WHERE storeId = ?', [storeId], (error) => {
            if (error) {
              console.error('Error deleting store: ' + error);
              res.status(500).send('Internal Server Error');
              return;
            }

            // Redirect to the adminstoredetails page after successful deletion
            res.redirect('/adminstoredetails');
          });

        });
      });
    }
  });
});

// Handle POST request to delete store details
app.post('/deletestore/:storeid', (req, res) => {
  const storeid = req.params.storeid;

  // Delete the store details from the database by storeId
  connection.query('DELETE FROM storesignin WHERE storeid = ?', [storeid], (error, results) => {
    if (error) {
      console.error('Error deleting store details: ' + error);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Redirect to the store details page after deleting
    res.redirect('/adminstoredetails');
  });
});


// Handle registration form submission
app.post('/storeregister', (req, res) => {
  const { name, contactname, place, gstnumber, mobilenumber, frompincode, topincode, password, confirmpassword } = req.body;

  // Check if the mobile number already exists in the database
  const mobileNumberQuery = `SELECT * FROM storesignin WHERE mobilenumber = ?`;
  connection.query(mobileNumberQuery, [mobilenumber], (err, mobileResults) => {
    if (err) {
      console.error('Error querying the database for mobile number: ', err);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (mobileResults.length > 0) {
      // Mobile number already exists, show an error message
      res.render('storemobilenumbererror');
      return;
    }

    // Check if the range (frompincode to topincode) already exists in the database
    const rangeQuery = `SELECT * FROM storesignin WHERE (frompincode <= ? AND topincode >= ?) OR (frompincode <= ? AND topincode >= ?)`;
    connection.query(rangeQuery, [frompincode, frompincode, topincode, topincode], (err, rangeResults) => {
      if (err) {
        console.error('Error querying the database for range: ', err);
        res.status(500).send('Internal Server Error');
        return;
      }

      if (rangeResults.length > 0) {
        // Range already exists, show an error message
        res.render('storepincodeerror');
        return;
      }

      // If neither mobile number nor range exists, you can proceed with the registration logic here.

      // Hash the password before storing it
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          console.error('Error hashing password:', err);
          res.status(500).send('Internal Server Error');
          return;
        }

        // Insert the registration data into the database with the hashed password
        const insertQuery = `INSERT INTO storesignin (name, contactname, place, gstnumber, mobilenumber, frompincode, topincode, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        connection.query(insertQuery, [name, contactname, place, gstnumber, mobilenumber, frompincode, topincode, hashedPassword], (err, result) => {
          if (err) {
            console.error('Error inserting data into the database: ', err);
            res.status(500).send('Internal Server Error');
            return;
          }
          res.render('storeregistersuccess');
        });
      });
    });
  });
});



// Serve the registration form page
// Serve the registration form page
app.get('/storesignup', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'storesignup.html'));
});






// Handle POST request to update store details
app.post('/updatestore/:storeid', (req, res) => {
  const storeid = req.params.storeid;
  const { name,contactname, place, gstnumber, mobilenumber, pincode, password } = req.body;

  // Update the store details in the database by storeId
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









//user***********

//usersignup

// Parse URL-encoded bodies (as sent by HTML forms)
app.use(express.urlencoded({ extended: true }));

app.post('/register', (req, res) => {
  const { name, mobilenumber, address, pincode, username, password } = req.body;

  // Hash the password
  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing password: ', err);
      res.status(500).json({ success: false, message: "An error occurred. Please try again later." });
      return;
    }

    // Check if the mobile number or pincode already exist in the database
    const query = `SELECT * FROM usersignin WHERE mobilenumber = ? `;
    connection.query(query, [mobilenumber], (err, results) => {
      if (err) {
        console.error('Error querying the database: ', err);
        res.status(500).json({ success: false, message: "An error occurred. Please try again later." });
        return;
      }

      if (results.length > 0) {
        // Mobile number already exists, send an error response
        res.render('usermobileerror');
      } else {
        // Insert the registration data into the database with hashed password
        const insertQuery = `INSERT INTO usersignin (name, mobilenumber, address, pincode, email, password) VALUES (?, ?, ?, ?, ?, ?)`;
        connection.query(insertQuery, [name, mobilenumber, address, pincode, username, hashedPassword], (err, result) => {
          if (err) {
            console.error('Error inserting data into the database: ', err);
            res.status(500).json({ success: false, message: "An error occurred. Please try again later." });
            return;
          }
          // Send a success response
          res.render('registration-success');
        });
      }
    });
  });
});






// app.get('/forgotpassword', (req, res) => {
//   res.sendFile(__dirname + '/forgotpassword.html');
// });




// // Route to display the password reset confirmation page
// app.get('/passwordresetconfirmation', (req, res) => {
//   res.send('<h1>Password Reset Successful!</h1><p>Your password has been reset. You can now log in with your new password.</p>');
// });



// app.post('/sendotp', async (req, res) => {
//   const mobileNumber = req.body.mobile;

//   // Generate a random OTP (You can use your own logic here)
//   const otp = generateOTP();

//   try {
//     await sendOTP(mobileNumber, otp);

//     // Save the OTP and the mobile number in the session for verification
//     req.session.mobileNumber = mobileNumber;
//     req.session.otp = otp;

//     // Redirect the user to the OTP verification page
//     res.redirect('/verifyotp');
//   } catch (error) {
//     console.error('Error sending OTP:', error);
//     res.status(500).json({ error: 'Error sending OTP. Please try again later.' });
//   }
// });


// app.get('/verifyotp', (req, res) => {
//   // Render the verifyotp.ejs template and pass the mobile number as a variable
//   res.render('verifyotp', { mobile: req.session.mobileNumber });
// });


// app.post('/verifyotp', (req, res) => {
//   const mobileNumber = req.session.mobileNumber;
//   const enteredOTP = req.body.otp;

//   // Check if the entered OTP matches the one saved in the session
//   if (enteredOTP === req.session.otp.toString()) {
//     // Redirect the user to the reset password page and pass the mobile number as a query parameter
//     res.redirect(`/resetpassword?mobile=${encodeURIComponent(mobileNumber)}`);
//   } else {
//     // Show an error message or redirect back to the OTP verification page with an error
//     res.send('<h1>OTP Verification Failed!</h1><p>The entered OTP is incorrect. Please try again.</p>');
//   }
// });

// // // Function to generate a random OTP
// function generateOTP() {
//   const digits = '0123456789';
//   let OTP = '';
//   for (let i = 0; i < 6; i++) {
//     OTP += digits[Math.floor(Math.random() * 10)];
//   }
//   return OTP;
// }


// // Function to send the OTP to the user's mobile number using Twilio

// async function sendOTP(mobileNumber, otp) {

// try {
//   // Create a new Twilio client with the provided credentials
//   const client = twilio(accountSid, authToken);

//   const messageBody = `Your OTP is: ${otp}`;

//   // Send SMS using Twilio API
//   const message = await client.messages.create({
//     body: messageBody,
//     from: twilioPhoneNumber,
//     to: mobileNumber,
//   });

//   console.log(`OTP sent to ${mobileNumber}: ${otp}`);
//   console.log('Twilio Response:', message); // Add this line to log the Twilio response

//   return message;
// } catch (error) {
//   console.error('Error sending OTP via Twilio:', error);
//   throw new Error('Error sending OTP'); // Throw a custom error to handle in the route
// }
// }

// // Route to generate and send OTP
// app.post('/generateotp', async (req, res) => {
//   const mobileNumber = req.body.mobile;
//   const otp = generateOTP();

//   try {
//     await sendOTP(mobileNumber, otp);
//     req.session.mobileNumber = mobileNumber;
//     req.session.otp = otp;
//     res.json({ message: 'OTP sent successfully' });
//   } catch (error) {
//     console.error('Error sending OTP:', error);
//     res.status(500).json({ error: 'Error sending OTP. Please try again later.' });
//   }
// });


// app.get('/resetpassword', (req, res) => {
//   const mobileNumber = req.query.mobile;
//   const token = req.query.token; // Get the token from the query parameters

//   // Check if the token exists and is valid in the database
//   const checkTokenQuery = `SELECT idusersignin FROM usersignin WHERE mobilenumber = '${mobileNumber}' AND reset_token = '${token}'`;
//   connection.query(checkTokenQuery, (error, results) => {
//     if (error) {
//       console.error('Error checking password reset token:', error);
//       return res.status(500).json({ error: 'Internal Server Error' });
//     }

//     // If the token is not found or invalid, show an error message or redirect back to the forgot password page
//     if (results.length === 0) {
//       return res.send('<h1>Invalid Token!</h1><p>The password reset link is invalid or has expired. Please try again.</p>');
//     }

//     // If the token is valid, render the resetpassword.ejs template and pass the mobile number as a variable
//     res.render('resetpassword', { mobile: mobileNumber, token: token });
//   });
// });


// // Route to handle the password reset form submission
// app.post('/resetpassword', (req, res) => {
//   const mobileNumber = req.body.mobile;
//   const newPassword = req.body.newPassword;
//   const token = req.body.token; // Get the token from the form submission

//   // Check if the token exists and is valid in the database again for double verification
//   const checkTokenQuery = `SELECT idusersignin FROM usersignin WHERE mobilenumber = '${mobileNumber}' AND reset_token = '${token}'`;
//   connection.query(checkTokenQuery, (error, results) => {
//     if (error) {
//       console.error('Error checking password reset token:', error);
//       return res.status(500).json({ error: 'Internal Server Error' });
//     }

//     // If the token is not found or invalid, show an error message or redirect back to the forgot password page
//     if (results.length === 0) {
//       return res.send('<h1>Invalid Token!</h1><p>The password reset link is invalid or has expired. Please try again.</p>');
//     }

//     // Update the new password in the database
//     updatePasswordInDatabase(mobileNumber, newPassword);

//     // Clear the reset_token in the database (optional step to invalidate the token after use)
//     const clearTokenQuery = `UPDATE usersignin SET reset_token = NULL WHERE mobilenumber = '${mobileNumber}'`;
//     connection.query(clearTokenQuery, (error) => {
//       if (error) {
//         console.error('Error clearing reset token:', error);
//       }
//     });

//     // Show a confirmation message to the user or redirect to the login page.
//     res.send('<h1>Password Reset Successful!</h1><p>Your password has been reset. You can now log in with your new password.</p>');
//   });
// });


// function updatePasswordInDatabase(mobileNumber, newPassword) {
//   const query = `UPDATE usersignin SET password = '${newPassword}' WHERE mobilenumber = '${mobileNumber}'`;
//   connection.query(query, (error, results) => {
//     if (error) {
//       console.error('Error updating password:', error);
//     }
//   });
// }


// Serve the registration form page
app.get('/usersignup', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', '/usersignup.html'));
});
// Route for serving the user login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// User login route

// ......

app.post('/userlogin', (req, res) => {
  const mobileNumber = req.body.mobilenumber;
  const password = req.body.password;

  if (!mobileNumber || !password) {
    return res.status(400).send('Mobile number and password are required');
  }

  // Determine the user type based on the table
  const userTypeQuery = `SELECT 'user' as type FROM usersignin WHERE mobilenumber = ? AND access = 1
                          UNION ALL
                          SELECT 'store' as type FROM storesignin WHERE mobilenumber = ?
                          UNION ALL
                          SELECT 'admin' as type FROM admin WHERE mobileNumber = ?`;

  const userTypeParams = [mobileNumber, mobileNumber, mobileNumber];

  connection.query(userTypeQuery, userTypeParams, (error, results) => {
    if (error) {
      console.error('Error authenticating user:', error);
      return res.status(500).send('Internal Server Error');
    }

    if (results.length === 0) {
      // return res.status(401).send('Invalid mobile number or password');
      return res.render('storeinvalidlogin');
    }

    const userType = results[0].type;

    if (userType === 'user') {
      // If the user type is 'user,' perform the user-specific login logic
      const query = `SELECT idusersignin, pincode, password, name FROM usersignin WHERE mobilenumber = ?`;
      connection.query(query, [mobileNumber], (error, userResults) => {
        if (error) {
          console.error('Error retrieving user:', error);
          return res.status(500).json({ error: 'Internal Server Error' });
        }
    
        if (userResults.length === 0) {
          return res.status(400).json({ error: 'Invalid mobile number' });
        }
    
        const userPincode = userResults[0].pincode;
        const storedPassword = userResults[0].password;
    
        // Compare the user-entered password with the stored, hashed password
        bcrypt.compare(password, storedPassword, (bcryptError, passwordMatch) => {
          if (bcryptError) {
            console.error('Error comparing passwords:', bcryptError);
            return res.status(500).json({ error: 'Internal Server Error' });
          }
          console.log('Password:', password);

          if (!passwordMatch) {
            return res.render('invalidpassworderror');
          }
    
          const idusersignin = userResults[0].idusersignin;
          req.session.idusersignin = idusersignin;
    
          const userName = userResults[0].name;
    
          // Check if the user's pincode falls within the range of any store
          const storeQuery = `SELECT storeid, name, frompincode, topincode FROM storesignin WHERE ? BETWEEN frompincode AND topincode`;
          connection.query(storeQuery, [userPincode], (error, storeResults) => {
            if (error) {
              console.error('Error retrieving store:', error);
              return res.status(500).json({ error: 'Internal Server Error' });
            }
    
            if (storeResults.length > 0) {
              const storeId = storeResults[0].storeid;
              const storeName = storeResults[0].name;
              req.session.storeId = storeId;
              req.session.storeName = storeName;
              req.session.userName = userName; // Store the userName in the session
    
              return res.redirect(`/userstoredetails/${storeId}`);
            } else {
              return res.status(400).json({ error: 'No stores found for the provided pincode' });
            }
          });
        });
      });
    
    } else if (userType === 'store') {
      console.log('Password:', password);

      // If the user type is 'store,' perform the store-specific login logic
      const storeQuery = 'SELECT storeid, password FROM storesignin WHERE mobilenumber = ?';
      connection.query(storeQuery, [mobileNumber], (storeError, storeResults) => {
        if (storeError) {
          console.error('Error retrieving store:', storeError);
          return res.status(500).send('Internal Server Error');
        }
        console.log('Password:', storeResults);

        if (storeResults.length === 0) {
          return res.status(400).send('Invalid mobile number');
        }

        const storedPassword = storeResults[0].password;

      
        // Compare the user-entered password with the stored, hashed password
        bcrypt.compare(password, storedPassword, (bcryptError, passwordMatch) => {
          if (bcryptError) {
            console.error('Error comparing passwords:', bcryptError);
            return res.status(500).send('Internal Server Error');
          }

          if (!passwordMatch) {
            console.log('Stored Password:', storedPassword);

            return res.render('invalidpassworderror');
          }

          const storeId = storeResults[0].storeid;
          // After successful store login
          req.session.storeId = storeId;
          res.redirect(`/storedetails/${storeId}`);
        });
      });
    } else if (userType === 'admin') {
      // If the user type is 'admin,' perform the admin-specific login logic
      const adminQuery = 'SELECT * FROM admin WHERE mobileNumber = ?';
      connection.query(adminQuery, [mobileNumber], (adminError, adminResults) => {
        if (adminError) {
          console.error('Error authenticating admin:', adminError);
          return res.status(500).send('Internal Server Error');
        }

        if (adminResults.length === 0) {
          // Authentication failed, handle as needed (e.g., display an error message)
          return res.status(401).send('Authentication failed');
        }

        const storedPassword = adminResults[0].password;

        // Compare the user-entered password with the stored, hashed password
        bcrypt.compare(password, storedPassword, (bcryptError, passwordMatch) => {
          if (bcryptError) {
            console.error('Error comparing passwords:', bcryptError);
            return res.status(500).send('Internal Server Error');
          }

          if (!passwordMatch) {
            return res.status(401).send('Invalid password');
          }

          // Authentication successful, redirect to the admin store details page
          res.redirect('/adminstoredetails');
        });
      });
    } else {
      res.status(401).send('Authentication failed');
    }
  });
});




// Server-side code (server.js)
app.get('/userstoredetails/:storeid', (req, res) => {
  // Check if user is authenticated
  if (!req.session.idusersignin) {
    return res.redirect('/login'); // Redirect to login page if not authenticated
  }

  const storeId = req.params.storeid;
  const page = parseInt(req.query.page) || 1; // Get the current page from query parameters
  const itemsPerPage = 10; // Set the number of products per page
  const selectedCategory = req.query.category || ''; // Get the selected category filter
 
  // Fetch the user's name and store name
  const userQuery = `
    SELECT usersignin.name AS userName, storesignin.name AS storeName
    FROM usersignin
    JOIN storesignin ON storesignin.storeid = ${storeId}
    WHERE usersignin.idusersignin = ?`;

  connection.query(userQuery, [req.session.idusersignin], (error, userResults) => {
    if (error) {
      console.error('Error fetching user and store:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    const userName = userResults[0].userName;
    const storeName = userResults[0].storeName;

    // Fetch products count for pagination with category filter
    const countQuery = 'SELECT COUNT(*) AS totalCount FROM products WHERE storeid = ? AND category LIKE ?';
    connection.query(countQuery, [storeId, `%${selectedCategory}%`], (error, countResults) => {
      if (error) {
        console.error('Error fetching products count:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
  
      
      const totalCount = countResults[0].totalCount;
      const totalPages = Math.ceil(totalCount / itemsPerPage); // Calculate the total number of pages

      // Calculate the starting index for the current page
      const startIndex = (page - 1) * itemsPerPage;
      console.log('selectedCategory');
      // Fetch products for the current page with category filter
      const productsQuery = 'SELECT productid, productname, salesprice FROM products WHERE storeid = ? AND category LIKE ? LIMIT ?, ?';
      connection.query(productsQuery, [storeId, `%${selectedCategory}%`, startIndex, itemsPerPage], (error, productResults) => {
        if (error) {
          console.error('Error fetching products:', error);
          return res.status(500).json({ error: 'Internal Server Error' });
        }

        const products = productResults;
        const productIds = products.map((product) => product.productid);

        // Fetch images for the products
        const imageQuery = 'SELECT imageid, imagepath, productid FROM images WHERE productid IN (?)';
        connection.query(imageQuery, [productIds], (error, imageResults) => {
          if (error) {
            console.error('Error fetching images:', error);
            return res.status(500).json({ error: 'Internal Server Error' });
          }

          const images = imageResults.map((image) => ({
            imagepath: image.imagepath,
            imageid: image.imageid,
            productid: image.productid,
          }));

          res.render('userstoredetails', {
            products,
            images,
            storeId,
            userName,
            storeName,
            currentPage: page,
            totalPages,
            selectedCategory, // Pass the selected category to the template
          });
        });
      });
      
    });
  });
});




// Product details page route
app.get('/productspage/:productid', (req, res) => {
  const productId = req.params.productid;

  const productQuery = 'SELECT * FROM products WHERE productid = ?';
  connection.query(productQuery, [productId], (error, results) => {
    if (error) {
      console.error('Error retrieving product:', error);
      res.render('productspage', { product: null, images: [], userName: null, storeName: null }); // Render with null product, userName, and storeName
    } else {
      if (results.length > 0) {
        const product = results[0];

        const imageQuery = 'SELECT imageid, imagepath, productid FROM images WHERE productid = ?';
        connection.query(imageQuery, [productId], (error, imageResults) => {
          if (error) {
            console.error('Error fetching images:', error);
            res.render('productspage', { product, images: [], userName: null, storeName: null });
          } else {
            const images = imageResults.map((image) => ({
              imagepath: image.imagepath,
              imageid: image.imageid,
              productid: image.productid,
            }));

            // Pass the userName and storeName from the session to the template
            res.render('productspage', {
              product,
              images,
              userName: req.session.userName,
              storeName: req.session.storeName
            });
          }
        });
      } else {
        console.log('Product not found for productid:', productId);
        res.render('productspage', { product: null, images: [], userName: null, storeName: null });
      }
    }
  });
});


// Buy Now route
app.post('/buynow', (req, res) => {
  const productid = req.body.productid;
  const quantity = parseInt(req.body.quantity);
  const userid = req.session.idusersignin; // Assuming you have stored the user ID in the session

  if (!userid) {
    res.status(401).send('Unauthorized');
    return;
  }

  // Check if the product is already in the cart for the user
  const checkCartQuery = 'SELECT * FROM cart WHERE userid = ? AND productid = ?';
  connection.query(checkCartQuery, [userid, productid], (error, results) => {
    if (error) {
      console.error('Error checking cart:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (results.length > 0) {
      // The product is already in the cart, update the quantity
      const updateQuantityQuery = 'UPDATE cart SET quantity = ? WHERE userid = ? AND productid = ?';
      connection.query(updateQuantityQuery, [quantity, userid, productid], (error) => {
        if (error) {
          console.error('Error updating cart quantity:', error);
          res.status(500).send('Internal Server Error');
          return;
        }
        // Redirect the user to the cart page
        res.redirect('/cart');
      });
    } else {
      // The product is not in the cart, insert a new cart item
      const insertCartQuery = 'INSERT INTO cart (userid, productid, quantity) VALUES (?, ?, ?)';
      connection.query(insertCartQuery, [userid, productid, quantity], (error) => {
        if (error) {
          console.error('Error adding to cart:', error);
          res.status(500).send('Internal Server Error');
          return;
        }
        // Retrieve the cart items for the logged-in user from the database
        const cartQuery = `
          SELECT cart.cartid, products.productid, products.productname, products.salesprice, cart.quantity, images.imagepath
          FROM cart
          INNER JOIN products ON cart.productid = products.productid
          INNER JOIN images ON products.productid = images.productid
          WHERE cart.userid = ?
        `;

        connection.query(cartQuery, [userid], (error, results) => {
          if (error) {
            console.error('Error retrieving cart items:', error);
            res.status(500).send('Internal Server Error');
          } else {
            const cartItems = results;

            // Calculate the total price of all cart items
            const totalPrice = cartItems.reduce((total, item) => total + item.salesprice * item.quantity, 0);

            // Render the cart page with the cart items and total price
            res.render('cart', { cartItems, totalPrice });
          }
        });
      });
    }
  });
});


// Assuming you have already established the 'connection' variable to the database

app.get('/cart', (req, res) => {
  const userId = req.session.idusersignin;
  if (!userId) {
    // Handle the case where userId is not set in the session
    return res.status(400).send('User not logged in.');
  }

  const cartQuery = `
    SELECT cart.cartid, products.productid, products.productname, products.salesprice, cart.quantity, 
    (SELECT imagepath FROM images WHERE images.productid = products.productid ORDER BY imageid ASC LIMIT 1) AS imagepath
    FROM cart
    INNER JOIN products ON cart.productid = products.productid
    WHERE cart.userid = ?
  `;

  connection.query(cartQuery, [userId], (error, results) => {
    if (error) {
      console.error('Error retrieving cart items:', error);
      res.status(500).send('Internal Server Error');
    } else {
      const cartItems = results;

      // Calculate the total price of all cart items
      const totalPrice = cartItems.reduce((total, item) => total + item.salesprice * item.quantity, 0);

      // Fetch the user's name and store name
      const userQuery = `
        SELECT usersignin.name AS userName, storesignin.name AS storeName
        FROM usersignin
        JOIN storesignin ON storesignin.frompincode <= usersignin.pincode AND storesignin.topincode >= usersignin.pincode
        WHERE usersignin.idusersignin = ?
      `;

      connection.query(userQuery, [userId], (error, userResults) => {
        if (error) {
          console.error('Error fetching user details:', error);
          res.status(500).send('Internal Server Error');
        } else {
          const userName = userResults[0].userName;
          const storeName = userResults[0].storeName;

          // Render the cart page with the cart items, total price, storeId, userName, and storeName
          res.render('cart', {
            cartItems,
            totalPrice,
            storeId: req.session.storeId,
            userName,
            storeName
          });
        }
      });
    }
  });
});


app.post('/cart', (req, res) => {
  const userId = req.session.idusersignin;
  const { cartId, quantity } = req.body;

  // Update the quantity of the cart item in the database
  const updateCartQuery = 'UPDATE cart SET quantity = ? WHERE cartid = ? AND userid = ?';
  connection.query(updateCartQuery, [quantity, cartId, userId], (error, results) => {
    if (error) {
      console.error('Error updating cart item:', error);
      res.status(500).send('Internal Server Error');
    } else {
      // Redirect the user back to the cart page
      res.redirect('/cart');
    }
  });
});

app.post('/removefromcart', (req, res) => {
  const userId = req.session.idusersignin;
  const cartId = req.body.cartid;

  const removeCartItemQuery = 'DELETE FROM cart WHERE cartid = ? AND userid = ?';
  connection.query(removeCartItemQuery, [cartId, userId], (error, results) => {
    if (error) {
      console.error('Error removing item from cart:', error);
      res.status(500).send('Internal Server Error');
    } else {
      // Item removed successfully, now fetch the updated cart items and total price
      const cartQuery = `
        SELECT cart.cartid, products.productid, products.productname, products.salesprice, cart.quantity, images.imagepath
        FROM cart
        INNER JOIN products ON cart.productid = products.productid
        INNER JOIN images ON images.productid = products.productid
        WHERE cart.userid = (SELECT idusersignin FROM usersignin WHERE idusersignin = ?)
        ORDER BY images.imageid ASC
      `;

      connection.query(cartQuery, [userId], (error, results) => {
        if (error) {
          console.error('Error retrieving cart items:', error);
          res.status(500).send('Internal Server Error');
        } else {
          const cartItems = results;

          // Calculate the total price of all cart items
          const totalPrice = cartItems.reduce((total, item) => total + item.salesprice * item.quantity, 0);

          // Send back the updated cart data in the response as JSON
          res.status(200).json({ cartItems, totalPrice });
        }
      });
    }
  });
});

app.get('/checkout', (req, res) => {
  const userId = req.session.idusersignin;

  // Retrieve the cart items for the logged-in user from the database
  const cartQuery = `
    SELECT cart.cartid, products.productid, products.productname, products.salesprice, cart.quantity
    FROM cart
    INNER JOIN products ON cart.productid = products.productid
    WHERE cart.userid = ?
  `;

  // Retrieve the user details from the database based on idusersignin
  const userQuery = 'SELECT name, address, mobilenumber FROM usersignin WHERE idusersignin = ?';

  // Retrieve the storename from the storesignin table based on the userId
  const storeQuery = `
    SELECT storesignin.name AS storename
    FROM storesignin
    INNER JOIN usersignin ON storesignin.frompincode <= usersignin.pincode AND storesignin.topincode >= usersignin.pincode
    WHERE usersignin.idusersignin = ?
  `;
  
  connection.query(cartQuery, [userId], (error, cartResults) => {
    if (error) {
      console.error('Error retrieving cart items:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    connection.query(userQuery, [userId], (userError, userResults) => {
      if (userError) {
        console.error('Error retrieving user details:', userError);
        res.status(500).send('Internal Server Error');
        return;
      }

      connection.query(storeQuery, [userId], (storeError, storeResults) => {
        if (storeError) {
          console.error('Error retrieving store name:', storeError);
          res.status(500).send('Internal Server Error');
          return;
        }

        const cartItems = cartResults;
        const totalPrice = cartItems.reduce((total, item) => total + item.salesprice * item.quantity, 0);

        // Extract the user details from the query results
        const user = {
          name: userResults[0].name.toString(),
          address: userResults[0].address,
          phoneNumber: userResults[0].mobilenumber,
        };

        // Extract the storename from the query results
        const storeName = storeResults[0].storename;

        // Render the checkout page with the cart items, total price, user details, and storename
        res.render('checkout', { cartItems, totalPrice, user, storeName });
      });
    });
  });
});



app.post('/checkout', (req, res) => {
  // Perform the necessary logic for processing the checkout
  // This can include updating the order status, generating invoices, etc.

  // Clear the cart after successful checkout
  const userId = req.session.idusersignin;

  const clearCartQuery = 'DELETE FROM cart WHERE userid = ?';
  connection.query(clearCartQuery, [userId], (error) => {
    if (error) {
      console.error('Error clearing cart:', error);
      res.status(500).send('Internal Server Error');
    } else {
      // Render the checkout success page
      res.render('checkout-success');
    }
  });
});

app.post('/placeorder', (req, res) => {
  // Retrieve the necessary data from the request
  const cartItems = JSON.parse(req.body.cartItems);
  const totalPrice = req.body.totalPrice;
  const userId = req.session.idusersignin; // Assuming you have stored the user ID in the session

  // Validate if the user is logged in
  if (!userId) {
    res.status(401).send('Unauthorized');
    return;
  }

  // Check if the cart is empty
  if (cartItems.length === 0) {
    res.redirect('/checkout');
    return;
  }


  // Perform the necessary steps to place the order
  // Here, you can update the database, create an order record, etc.
  // You can customize this logic based on your application's requirements

  // Clear the cart after placing the order
  const clearCartQuery = 'DELETE FROM cart WHERE userid = ?';
  connection.query(clearCartQuery, [userId], (error) => {
    if (error) {
      console.error('Error clearing the cart:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Render the order confirmation page or redirect to a success page
    res.render('orderConfirmation');
  });
});



// Serve the edit profile page
app.get('/editprofile', (req, res) => {
  const idusersignin = req.session.idusersignin;

  if (!idusersignin) {
    res.redirect('/user.html');
    return;
  }

  const query = 'SELECT * FROM usersignin WHERE idusersignin = ?';
  connection.query(query, [idusersignin], (error, results) => {
    if (error) {
      console.error('Error fetching user details:', error);
      res.send('Error fetching user details');
    } else {
      if (results.length > 0) {
        res.render('editprofile', { user: results[0] });
      } else {
        res.send('User not found');
      }
    }
  });
});


// Update profile route

app.post('/updateprofile', (req, res) => {
  const idusersignin = req.session.idusersignin;
  const { name, mobilenumber, address, email, password } = req.body;

  // Retrieve the user's pincode from the database
  const getPincodeQuery = 'SELECT pincode FROM usersignin WHERE idusersignin = ?';

  connection.query(getPincodeQuery, [idusersignin], (pincodeError, pincodeResults) => {
    if (pincodeError) {
      console.error('Error fetching pincode:', pincodeError);
      res.send('Error fetching pincode');
    } else {
      if (pincodeResults.length > 0) {
        const pincode = pincodeResults[0].pincode;

  

        const updateQuery =
          'UPDATE usersignin SET name=?, mobilenumber=?, address=?, email=?, password=? WHERE idusersignin=?';
        connection.query(
          updateQuery,
          [name, mobilenumber, address, email, password, idusersignin],
          (error, results) => {
            if (error) {
              console.error('Error updating profile:', error);
              res.send('Error updating profile');
            } else {
              const storeIdQuery = 'SELECT storeid FROM storesignin WHERE frompincode <= ? AND topincode >= ?';
              connection.query(storeIdQuery, [pincode, pincode], (storeIdError, storeResults) => {
                if (storeIdError) {
                  console.error('Error fetching store ID:', storeIdError);
                  res.send('Error fetching store ID');
                } else {
                  if (storeResults.length > 0) {
                    const storeId = storeResults[0].storeid;
                    res.send(`<script>alert("Profile updated successfully"); window.location.href = "/userstoredetails/${storeId}";</script>`);
                  } else {
                    res.send('Store ID not found');
                  }
                }
              });
            }
          }
        );
      } else {
        res.send('Pincode not found for the user');
      }
    }
  });
});


//store****

//storesignup

// Parse URL-encoded bodies (as sent by HTML forms)
//app.use(express.urlencoded({ extended: true }));




app.get('/storedetails/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  const currentPage = parseInt(req.query.page) || 1; // Current page number
  const itemsPerPage = 5; // Number of items to display per page

  const storeQuery = 'SELECT storeid, name FROM storesignin WHERE storeid = ?';
  connection.query(storeQuery, [storeId], (error, storeResults) => {
    if (error) {
      console.error('Error fetching store:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (storeResults.length > 0) {
      const storeId = storeResults[0].storeid;
      const name = storeResults[0].name;

      const productsQuery = 'SELECT p.productid, p.productname, p.category, p.code, p.hsn, p.salesprice, p.mrp, p.qty, p.description FROM products AS p WHERE p.storeid = ?';
      connection.query(productsQuery, [storeId], (error, productsResults) => {
        if (error) {
          console.error('Error fetching products:', error);
          res.status(500).send('Internal Server Error');
          return;
        }

        const products = productsResults;

        if (products.length === 0) {
          // No products in the store
          res.render('storedetails', {
            storeId,
            name,
            products: [],
            images: [],
            currentPage: 1,
            totalPages: 1,
            totalProducts: 0, // Add totalProducts here
          });
          return;
        }

        // Calculate the total count of products
        const totalProducts = products.length;

        const productIds = products.map((product) => product.productid);
        const imageQuery = 'SELECT imageid, imagepath, productid FROM images WHERE productid IN (?)'; // Use placeholder for productIds

        connection.query(imageQuery, [productIds], (error, imageResults) => {
          if (error) {
            console.error('Error fetching images:', error);
            res.status(500).send('Internal Server Error');
            return;
          }

          const images = imageResults.map((image) => ({
            imagepath: image.imagepath,
            imageid: image.imageid,
            productid: image.productid,
          }));

          const startIndex = (currentPage - 1) * itemsPerPage;
          const endIndex = startIndex + itemsPerPage;
          const paginatedProducts = products.slice(startIndex, endIndex);
          const totalPages = Math.ceil(products.length / itemsPerPage);

          res.render('storedetails', {
            storeId,
            name,
            products: paginatedProducts,
            images,
            currentPage,
            totalPages,
            totalProducts, // Pass totalProducts here
          });
        });
      });
    } else {
      res.render('storedetails', {
        storeId,
        name: '',
        products: [],
        images: [],
        currentPage: 1,
        totalPages: 1,
        totalProducts: 0, // Add totalProducts here
      });
    }
  });
});


app.get('/storeuserdetails/:pincode', (req, res) => {
  const pincode = req.params.pincode;

  // Add your database query to fetch user details based on the pincode
  const userDetailsQuery = 'SELECT name, mobilenumber, address, pincode, email FROM usersignin WHERE pincode = ?';

  connection.query(userDetailsQuery, [pincode], (error, userDetails) => {
    if (error) {
      console.error('Error fetching user details:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Render the storeuserdetails.ejs template with the retrieved user details
    res.render('storeuserdetails', { userDetails });
  });
});

// Serve the edit store page
// Serve the edit store page
app.get('/editstore/:storeid', (req, res) => {
  const storeId = req.params.storeid;

  // Query the database to get store details using storeId
  const query = 'SELECT * FROM storesignin WHERE storeid = ?';
  connection.query(query, [storeId], (error, results) => {
    if (error) {
      console.error('Error fetching store details:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (results.length > 0) {
      // Render the edit store page with store details
      res.render('editstore', { store: results[0] });
    } else {
      res.status(404).send('Store not found');
    }
  });
});

// Update store details route
// Update store details route
// Update store details route
app.post('/updatestore/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  const { name, contactname, place, gstnumber, mobilenumber, frompincode, topincode, password } = req.body;

  // Hash the password before updating the store details
  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing password:', err);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Update the store details in the database with the hashed password
    connection.query(query, [name, contactname, place, gstnumber, mobilenumber, frompincode, topincode, hashedPassword, storeId], (error, results) => {
      if (error) {
        console.error('Error updating store details:', error);
        res.status(500).send('Failed to update store details. Please try again.');
        return;
      }

      // Redirect back to the edit store page with a success message
      res.redirect(`/editstore/${storeId}`);
    });
  });
});






app.get('/editproduct/:storeId/:productId', (req, res) => {
  const storeId = req.params.storeId;
  const productId = req.params.productId;

  // Query the product details from the database
  const productQuery = 'SELECT * FROM products WHERE storeid = ? AND productid = ?';
  connection.query(productQuery, [storeId, productId], (error, productResults) => {
    if (error) {
      console.error('Error fetching product details:', error);
      res.status(500).send('Internal Server Error');
      return;
    }

    if (productResults.length > 0) {
      const product = productResults[0];

      // Query the images for the product
      const imageQuery = 'SELECT * FROM images WHERE productid = ?';
      connection.query(imageQuery, [productId], (error, imageResults) => {
        if (error) {
          console.error('Error fetching images:', error);
          res.status(500).send('Internal Server Error');
          return;
        }

        const images = imageResults;

        res.render('editproduct', { product, images }); // Render the editproduct.ejs template
      });
    } else {
      res.status(404).send('Product not found');
    }
  });
});


// ... previous code ...
app.post('/updateproduct/:storeId/:productId', (req, res) => {
  const storeId = req.params.storeId;
  const productId = req.params.productId;
  const updatedProduct = req.body;

  // Update the product details in the database
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

      // Handle file upload and update images
      if (req.files && req.files.newImages) {
        const newImages = Array.isArray(req.files.newImages) ? req.files.newImages : [req.files.newImages];

        // Delete the old images
        const deleteImagesQuery = 'DELETE FROM images WHERE productid = ?';
        connection.query(deleteImagesQuery, [productId], (error) => {
          if (error) {
            console.error('Error deleting old images:', error);
            res.status(500).send('Internal Server Error');
            return;
          }

          // Process each new image
          newImages.forEach((image) => {
            // Save the image file to a folder (e.g., '/images/') on your server
            const imagePath = '/images/' + image.name;
            image.mv('public' + imagePath, (error) => {
              if (error) {
                console.error('Error saving image:', error);
              } else {
                // Insert the image details into the database
                const insertImageQuery = 'INSERT INTO images (imagepath, productid) VALUES (?, ?)';
                connection.query(insertImageQuery, [imagePath, productId], (error) => {
                  if (error) {
                    console.error('Error inserting image:', error);
                  }
                });
              }
            });
          });
          res.redirect(`/storedetails/${storeId}`); // Redirect back to the edit product page
        });
      } else {
        res.redirect(`/storedetails/${storeId}`); // Redirect back to the edit product page
      }
    }
  );
});


// ... previous code ...
// GET route for rendering the form to replace the image
app.get('/replaceimage/:productid/:imageid', (req, res) => {
  const productId = req.params.productid;
  const imageId = req.params.imageid;

  // Fetch the existing image path from the database based on productid and imageid
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

    // Render the form to replace the image
    res.render('replaceimage', { productId, imageId, existingImagePath });
  });
});
// POST route to handle the image replacement
// POST route to handle the image replacement
app.post('/replaceimage/:productid/:imageid', upload.single('newImage'), (req, res) => {
  const productId = req.params.productid;
  const imageId = req.params.imageid;

  if (!req.file) {
    res.status(400).send('No image file selected');
    return;
  }

  // Fetch the existing image path from the database based on productid and imageid
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

    // Check if the file exists before attempting to delete it
    if (!fs.existsSync(existingImagePath)) {
      console.error('Image file not found:', existingImagePath);
      res.status(404).send('Image not found');
      return;
    }
    try {
      // Delete the old image from the filesystem
      fs.unlinkSync(existingImagePath);

      // Save the new image with the same path and filename in the filesystem
      const newImagePath = path.join(__dirname, 'public', 'images', req.file.originalname);
      fs.renameSync(req.file.path, newImagePath);

      // Update the imagepath and imageid in the database with the new image details
      const updateImageQuery = 'UPDATE images SET imagepath = ?, imageid = ? WHERE productid = ? AND imageid = ?';
      connection.query(updateImageQuery, [newImagePath, req.file.originalname, productId, imageId], (updateError) => {
        if (updateError) {
          console.error('Error updating image path in the database:', updateError);
          res.status(500).send('Internal Server Error');
          return;
        }

        // Redirect back to the edit product page
        res.redirect(`/editproduct/${productId}`);
      });
    } catch (error) {
      console.error('Error during image replacement:', error);
      res.status(500).send('Internal Server Error');
    }
  });
});
// Route to get store details for a given store ID
app.get('/editstore/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  // Access the 'connection' variable using app.locals.connection
  const connection = req.app.locals.connection;

  // Fetch the store details from the database based on the storeId
  const sql = 'SELECT * FROM storesignin WHERE storeid = ?';
  connection.query(sql, [storeId], (err, results) => {
    if (err) {
      console.error('Error fetching store details:', err);
      res.status(500).json({ error: 'Failed to fetch store details. Please try again later.' });
    } else if (results.length === 0) {
      res.status(404).json({ error: 'Store not found.' });
    } else {
      const storeDetails = results[0];
      // Render the editstore.html template with the fetched store details
      res.render('editstore', { storeDetails });
    }
  });
});

app.get('/addproduct/:storeid', (req, res) => {
  const storeId = req.params.storeid;
  res.render('addproduct', { storeId });
});

app.post('/addproduct/:storeid', upload.array('images', 8), (req, res) => {
  const storeId = req.params.storeid;
  const { productname, category, code, hsn, salesprice, mrp, qty, description, removedImages } = req.body;

  const addProductQuery =
    'INSERT INTO products (storeid, productname, category, code, hsn, salesprice, mrp, qty, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
  connection.query(
    addProductQuery,
    [storeId, productname, category, code, hsn, salesprice, mrp, qty, description],
    (error, results) => {
      if (error) {
        console.error('Error adding product:', error);
        res.status(500).send('Internal Server Error');
      } else {
        const productId = results.insertId;
        const files = req.files;

        const imagePaths = files.map((file, index) => [productId, file.filename, index + 1]);

        // Remove the removed images from the imagePaths array
        const removedImageIds = removedImages || [];
        const filteredImagePaths = imagePaths.filter((imagePath) => {
          const [, , imageIndex] = imagePath;
          return !removedImageIds.includes(imageIndex.toString());
        });

        // Construct the multi-row insert statement for images
        if (filteredImagePaths.length > 0) {
          const addImagesQuery = 'INSERT INTO images (productid, imagepath, imageid) VALUES ?';
          connection.query(addImagesQuery, [filteredImagePaths], (addError) => {
            if (addError) {
              console.error('Error adding image paths:', addError);
              res.status(500).send('Internal Server Error');
            } else {
              // Delete the removed images from the server's file system
              removedImageIds.forEach((imageIndex) => {
                const removedImage = files[parseInt(imageIndex) - 1];
                if (removedImage) {
                  fs.unlink(removedImage.path, (error) => {
                    if (error) {
                      console.error('Error deleting image:', error);
                    }
                  });
                }
              });

              res.redirect(`/storedetails/${storeId}`);
            }
          });
        } else {
          // No images to insert, simply redirect to store details page
          res.redirect(`/storedetails/${storeId}`);
        }
      }
    }
  );
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

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

