// Use the Fetch API to send a POST request to log out
function logout() {
  fetch('/logout', {
      method: 'POST'
  })
  .then(response => response.json())
  .then(data => {
      if (data.message) {
          console.log(data.message);  // "Logout successful"
          document.getElementById("loginButton").style.display = "inline-block";
          document.getElementById("userDropdown").style.display = "none";
      }
  })
  .catch(error => {
      console.error('Error during logout:', error);
  });
}

$(document).ready(function () {

  $(document).ready(function () {
    $("#loginActionBtn").on("click", function () {
      var userID = $("#userID").val();
      var userPassword = $("#userPassword").val();

      // Check if the user ID and password are entered
      if (userID && userPassword) {
        // Send an AJAX request to the backend login endpoint
        $.ajax({
          url: '/login',
          type: 'POST',
          contentType: 'application/json',
          data: JSON.stringify({
            username: userID,
            password: userPassword
          }),
          success: function (response) {
            // Handling for successful login
            document.getElementById("loginButton").style.display = "none";
            document.getElementById("userDropdown").style.display = "inline";
            $("#loginModal").modal("hide");
            document.getElementById("usernameDisplay").innerText = userID;
          },
          error: function (xhr, status, error) {
            alert(xhr.responseJSON.message || "Login failed! Wrong ID or password!");
          }
        });
      } else {
        alert("Please enter both username and password.");
      }
    });
  });


  // Show the registration modal
  $("#showRegisterModal").on("click", function (e) {
    e.preventDefault();

    // Close the login modal
    $("#loginModal").modal("hide");

    // Show the register modal after a short delay to ensure smooth transition
    setTimeout(function () {
      $("#registerModal").modal("show");
    }, 500);
  });

  $("#registerBtn").on("click", function () {
    var registeredID = $("#registerUsername").val();
    var registeredPassword = $("#registerPassword").val();

    if (registeredID && registeredPassword) {
      $.ajax({
        url: '/register',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
          username: registeredID,
          password: registeredPassword
        }),
        success: function (response) {
          // Close the window
          $("#registerModal").modal("hide");

          // Display a success message
          alert("Registration success!");
        },
        error: function (xhr, status, error) {
          alert(xhr.responseJSON.message || "Registration failed!");
        }
      });
    } else {
      alert("Please enter a valid username and password.");
    }
  });

});
