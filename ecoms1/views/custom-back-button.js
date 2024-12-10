<script>
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
  window.onpageshow = function(event) {
    if (event.persisted) {
      window.location.reload();
    }
  };

  history.pushState(null, null, location.href);
  window.onpopstate = function() {
    history.go(1);
  };
}
</script>