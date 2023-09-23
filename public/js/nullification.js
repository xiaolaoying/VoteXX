$(document).ready(function () {
  $("#nullifyBtn").on("click", function () {
    var secretKey = $("#secretKey").val(); // Retrieve the value of the 'secretKey' input field

    // Use the Fetch API to send data
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
            window.location.href = "profile"; // Navigate to profile
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
