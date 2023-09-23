$(function () {
  $("#sortable").sortable();
  $("#sortable").disableSelection();
});

function submitVote() {
  let sortedAnimals = $("#sortable").sortable("toArray", {
    attribute: "data-value",
  });

  console.log(sortedAnimals); // Output the sorted results
  // Here, you can send the sorted results to the server
}

document
  .getElementById("voteform")
  .addEventListener("submit", function (event) {
    event.preventDefault();
    // Here, you can add the actual form submission code
    $("#successModal").modal("show"); 
  });

$("#successModal").on("hidden.bs.modal", function () {
  window.location.href = "profile.html"; // Navigate to profile
});
