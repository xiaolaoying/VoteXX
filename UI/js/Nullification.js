function nullificate() {
  const secretKey = document.getElementById("secretKey").value;

  fetch("/nullificate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ secretKey: secretKey }),
  })
    .then((response) => response.json())
    .then((data) => {
      document.getElementById("responseMessage").textContent = data.message;
    })
    .catch((error) => {
      console.error("Error:", error);
    });
}
