function login() {
  // 隐藏登录按钮
  document.getElementById("loginButton").style.display = "none";

  // 显示用户名
  document.getElementById("userDropdown").style.display = "inline";
}

function logout() {
  document.getElementById("loginButton").style.display = "inline-block";
  document.getElementById("userDropdown").style.display = "none";
}
