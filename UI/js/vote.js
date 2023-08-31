$(function () {
  $("#sortable").sortable();
  $("#sortable").disableSelection();
});

function submitVote() {
  let sortedAnimals = $("#sortable").sortable("toArray", {
    attribute: "data-value",
  });

  console.log(sortedAnimals); // 输出排序后的结果
  // 这里，你可以将排序后的结果发送到服务器
}

document
  .getElementById("voteform")
  .addEventListener("submit", function (event) {
    event.preventDefault();
    // 在这里你可以添加实际的表单提交代码
    $("#successModal").modal("show"); 
  });

$("#successModal").on("hidden.bs.modal", function () {
  window.location.href = "profile.html"; // 导航到 profile.html 页面
});
