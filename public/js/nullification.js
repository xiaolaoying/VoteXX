$(document).ready(function () {
  $("#nullifyBtn").on("click", function () {
    var secretKey = $("#secretKey").val(); // 获取secretKey输入字段的值

    if (secretKey === "123") {
      // 如果值是123
      $("#modalMessage").text("Nullification success!"); // 设置模态框的消息内容
      $("#myModal").modal("show"); // 显示模态框

      // 当模态框关闭时，导航到profile.html
      $("#myModal").on("hidden.bs.modal", function () {
        window.location.href = "profile.html"; // 导航到profile.html
      });
    } else {
      $("#modalMessage").text("Wrong key!"); // 设置模态框的消息内容
      $("#myModal").modal("show"); // 显示模态框
    }
  });
});
