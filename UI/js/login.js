function logout() {
  document.getElementById("loginButton").style.display = "inline-block";
  document.getElementById("userDropdown").style.display = "none";
}

$(document).ready(function () {
  $("#loginActionBtn").on("click", function () {
    var userID = $("#userID").val();
    var userPassword = $("#userPassword").val();

    if (userID === "123" && userPassword === "123") {
      // 隐藏登录按钮
      document.getElementById("loginButton").style.display = "none";

      // 显示用户名
      document.getElementById("userDropdown").style.display = "inline";

      // 关闭模态框
      $("#loginModal").modal("hide");
    } else {
      alert("Login failed! Wrong ID or password!");
    }
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

  // 注册
  $("#registerBtn").on("click", function () {
    // ID
    var registeredID = $("#registerUsername").val();

    // 验证有效
    if (registeredID) {
      // 关闭窗口
      $("#registerModal").modal("hide");

      // 隐藏登录按钮
      document.getElementById("loginButton").style.display = "none";

      // 显示用户名
      document.getElementById("userDropdown").style.display = "inline";

      // Display a success message
      alert("Registration success!");
    } else {
      alert("Please enter a valid username.");
    }
  });
});
