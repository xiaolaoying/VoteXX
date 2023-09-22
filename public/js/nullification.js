$(document).ready(function () {
  $("#nullifyBtn").on("click", function () {
    var secretKey = $("#secretKey").val(); // 获取secretKey输入字段的值

    // 使用 fetch API 发送数据
    fetch(window.location.href, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      }
    })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          $("#modalMessage").text("Nullification success!");
          $("#myModal").modal("show");
          $("#myModal").on("hidden.bs.modal", function () {
            window.location.href = "profile"; // 导航到profile.html
          });
        } else {
          alert("Error: " + data.message);
        }
      })
      .catch(error => {
        console.error('There was an error submitting the form:', error);
        alert('There was an error submitting the form.');
      });

  });
});
