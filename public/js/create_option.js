// Add a new question to the poll container
function addQuestionField() {
  const pollContainer = document.getElementById("pollContainer");

  // Get the current number of questions to set the new question's index
  const questionNumber =
    pollContainer.getElementsByClassName("questionDiv").length + 1;

  // Create a new container for the question
  const questionDiv = document.createElement("div");
  questionDiv.className = "questionDiv";

  // Create and set the label for the question index
  const questionLabel = document.createElement("span");
  questionLabel.textContent = questionNumber + ". ";
  questionDiv.appendChild(questionLabel);

  // Create a row container using Bootstrap's grid system
  const rowDiv = document.createElement("div");
  rowDiv.className = "row input-spacing";
  questionDiv.appendChild(rowDiv);

  // Create a column container to hold the question type dropdown
  const questionTypeCol = document.createElement("div");
  questionTypeCol.className = "col-md-3";
  rowDiv.appendChild(questionTypeCol);

  // Create a dropdown for question types
  const questionTypeSelect = document.createElement("select");
  questionTypeSelect.className = "form-control";
  const types = ["Single Choice", "Multiple Choice", "Ranking", "Yes-No"];
  types.forEach((type) => {
    const option = document.createElement("option");
    option.value = type;
    option.textContent = type;
    questionTypeSelect.appendChild(option);
  });
  questionTypeCol.appendChild(questionTypeSelect);

  // Create a column container to hold the question input box
  const questionInputCol = document.createElement("div");
  questionInputCol.className = "col-md-9";
  rowDiv.appendChild(questionInputCol);

  // Create an input group for the question
  const questionInputGroup = document.createElement("div");
  questionInputGroup.className = "input-group input-spacing";
  questionInputCol.appendChild(questionInputGroup);

  // Create and set the question input box
  const questionInput = document.createElement("input");
  questionInput.type = "text";
  questionInput.className = "form-control";
  questionInput.placeholder = "Enter question";
  questionInputGroup.appendChild(questionInput);

  // Create the button to delete the question
  const deleteButtonSpan = document.createElement("span");
  deleteButtonSpan.className = "input-group-btn";
  questionInputGroup.appendChild(deleteButtonSpan);

  const deleteQuestionButton = document.createElement("button");
  deleteQuestionButton.className = "btn btn-danger";
  deleteQuestionButton.textContent = "Delete Question";
  deleteQuestionButton.onclick = function () {
    pollContainer.removeChild(questionDiv);
    updateQuestionIndices(pollContainer); // Update indices for other questions
  };
  deleteButtonSpan.appendChild(deleteQuestionButton);

  // Create the option list container
  const optionList = document.createElement("div");
  questionDiv.appendChild(optionList);

  // Create the button to add options
  const addOptionButton = document.createElement("button");
  addOptionButton.type = "button";
  addOptionButton.className = "btn btn-secondary input-spacing";
  addOptionButton.textContent = "Add Option";
  addOptionButton.onclick = function () {
    addOptionField(optionList); // Add a new option to the list
  };
  questionDiv.appendChild(addOptionButton);

  // Listen for changes on questionTypeSelect
  questionTypeSelect.addEventListener("change", function () {
    // Decide whether to show or hide the Add Option button based on the selected type
    if (questionTypeSelect.value === "Yes-No") {
      addOptionButton.style.display = "none"; // Hide the button
    } else {
      addOptionButton.style.display = "block"; // Show the button
    }
  });

  // Initial setup to make sure the button is in the correct state when the question is created
  if (questionTypeSelect.value === "Yes-No") {
    addOptionButton.style.display = "none";
  } else {
    addOptionButton.style.display = "block";
  }

  // Add the question container to the main container
  pollContainer.appendChild(questionDiv);
}

// Add a new option to the specified option list
function addOptionField(optionList) {
  const optionDiv = document.createElement("div");
  optionDiv.className = "input-group input-spacing";

  // Create index span
  const indexSpan = document.createElement("span");
  indexSpan.className = "input-group-addon"; // Bootstrap 3 uses input-group-addon
  optionDiv.appendChild(indexSpan);

  // Create the option input field
  const optionInput = document.createElement("input");
  optionInput.type = "text";
  optionInput.className = "form-control";
  optionInput.placeholder = "Enter option";
  optionDiv.appendChild(optionInput);

  // Create a container for the delete option button
  const deleteButtonSpan = document.createElement("span");
  deleteButtonSpan.className = "input-group-btn"; // Bootstrap 3 uses input-group-btn
  optionDiv.appendChild(deleteButtonSpan);

  // Create the delete option button
  const deleteButton = document.createElement("button");
  deleteButton.className = "btn btn-danger";
  deleteButton.textContent = "Delete";
  deleteButton.onclick = function () {
    optionList.removeChild(optionDiv);
    updateOptionIndices(optionList); // Update the indices of the options
  };
  deleteButtonSpan.appendChild(deleteButton); // Add the button to its container

  optionList.appendChild(optionDiv);

  // Update the option indices
  updateOptionIndices(optionList);
}

// Update the indices of the options
function updateOptionIndices(optionList) {
  const questionDiv = optionList.parentElement;
  const pollContainer = document.getElementById("pollContainer");
  const questions = pollContainer.getElementsByClassName("questionDiv");
  let questionIndex = 1;
  for (let i = 0; i < questions.length; i++) {
    if (questions[i] === questionDiv) {
      questionIndex = i + 1;
      break;
    }
  }

  const optionDivs = optionList.getElementsByClassName("input-group");
  for (let i = 0; i < optionDivs.length; i++) {
    const indexSpan =
      optionDivs[i].getElementsByClassName("input-group-addon")[0];
    indexSpan.textContent = questionIndex + "." + (i + 1);
  }
}

// Update the indices of the questions
function updateQuestionIndices(pollContainer) {
  const questions = pollContainer.getElementsByClassName("questionDiv");
  for (let i = 0; i < questions.length; i++) {
    // Update the index of the question
    const questionLabel = questions[i].getElementsByTagName("span")[0];
    questionLabel.textContent = i + 1 + ". ";

    // Update the indices of all options under this question
    const optionList = questions[i].lastElementChild.previousElementSibling;
    // Based on the current DOM structure, optionList should be the element just before the last child of questionDiv
    if (optionList) {
      updateOptionIndices(optionList);
    }
  }
}

document.getElementById("Election").addEventListener("submit", function (event) {
  event.preventDefault();

  // 1. Extract form data
  const formData = new FormData(event.target);
  const data = {};
  formData.forEach((value, key) => {
    data[key] = value;
  });

  // 2. Use fetch API to send data
  fetch('/createElection', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        $("#successModal").modal("show");
      } else {
        alert("Error: " + data.message);
      }
    })
    .catch(error => {
      console.error('There was an error submitting the form:', error);
      alert('There was an error submitting the form.');
    });
});

$("#successModal").on("hidden.bs.modal", function () {
  window.location.href = "profile"; // Navigate to the profile page
});
