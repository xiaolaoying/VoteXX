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
