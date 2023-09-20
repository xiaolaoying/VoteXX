// 使用 Fetch API 发送 POST 请求实现登出
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

      // 检查用户ID和密码是否输入
      if (userID && userPassword) {
        // 发送AJAX请求到后端登录端点
        $.ajax({
          url: '/login',
          type: 'POST',
          contentType: 'application/json',
          data: JSON.stringify({
            username: userID,
            password: userPassword
          }),
          success: function (response) {
            // 登录成功的处理
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


  // 显示注册页面
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
          // 关闭窗口
          $("#registerModal").modal("hide");

          // 显示成功消息
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
