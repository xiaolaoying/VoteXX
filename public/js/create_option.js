// 添加一个新的问题到投票容器中
function addQuestionField() {
  const pollContainer = document.getElementById("pollContainer");

  // 获取当前的问题数量，以设置新问题的序号
  const questionNumber =
    pollContainer.getElementsByClassName("questionDiv").length + 1;

  // 创建新问题的容器
  const questionDiv = document.createElement("div");
  questionDiv.className = "questionDiv";

  // 创建并设置问题的序号标签
  const questionLabel = document.createElement("span");
  questionLabel.textContent = questionNumber + ". ";
  questionDiv.appendChild(questionLabel);

  // 使用Bootstrap的网格系统创建一个行容器
  const rowDiv = document.createElement("div");
  rowDiv.className = "row input-spacing";
  questionDiv.appendChild(rowDiv);

  // 创建一个列容器来放置问题类型选择框
  const questionTypeCol = document.createElement("div");
  questionTypeCol.className = "col-md-3";
  rowDiv.appendChild(questionTypeCol);

  // 创建问题类型选择下拉框
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

  // 创建一个列容器来放置问题输入框
  const questionInputCol = document.createElement("div");
  questionInputCol.className = "col-md-9";
  rowDiv.appendChild(questionInputCol);

  // 创建问题输入框组
  const questionInputGroup = document.createElement("div");
  questionInputGroup.className = "input-group input-spacing";
  questionInputCol.appendChild(questionInputGroup);

  // 创建并设置问题输入框
  const questionInput = document.createElement("input");
  questionInput.type = "text";
  questionInput.className = "form-control";
  questionInput.placeholder = "Enter question";
  questionInputGroup.appendChild(questionInput);

  // 创建删除问题的按钮
  const deleteButtonSpan = document.createElement("span");
  deleteButtonSpan.className = "input-group-btn";
  questionInputGroup.appendChild(deleteButtonSpan);

  const deleteQuestionButton = document.createElement("button");
  deleteQuestionButton.className = "btn btn-danger";
  deleteQuestionButton.textContent = "Delete Question";
  deleteQuestionButton.onclick = function () {
    pollContainer.removeChild(questionDiv);
    updateQuestionIndices(pollContainer); // 更新其他问题的序号
  };
  deleteButtonSpan.appendChild(deleteQuestionButton);

  // 创建选项列表容器
  const optionList = document.createElement("div");
  questionDiv.appendChild(optionList);

  // 创建添加选项的按钮
  const addOptionButton = document.createElement("button");
  addOptionButton.type = "button";
  addOptionButton.className = "btn btn-secondary input-spacing";
  addOptionButton.textContent = "Add Option";
  addOptionButton.onclick = function () {
    addOptionField(optionList); // 添加新选项到列表
  };
  questionDiv.appendChild(addOptionButton);

  // 监听questionTypeSelect的改变事件
  questionTypeSelect.addEventListener("change", function () {
    // 根据选择的类型来决定是否显示添加选项按钮
    if (questionTypeSelect.value === "Yes-No") {
      addOptionButton.style.display = "none"; // 隐藏按钮
    } else {
      addOptionButton.style.display = "block"; // 显示按钮
    }
  });

  // 初始设置，以确保在创建问题时按钮处于正确的状态
  if (questionTypeSelect.value === "Yes-No") {
    addOptionButton.style.display = "none";
  } else {
    addOptionButton.style.display = "block";
  }

  // 将问题容器添加到主容器中
  pollContainer.appendChild(questionDiv);
}

// 添加新选项到指定的选项列表中
function addOptionField(optionList) {
  const optionDiv = document.createElement("div");
  optionDiv.className = "input-group input-spacing";

  // 创建序号span
  const indexSpan = document.createElement("span");
  indexSpan.className = "input-group-addon"; // Bootstrap 3 使用 input-group-addon
  optionDiv.appendChild(indexSpan);

  // 创建选项输入框
  const optionInput = document.createElement("input");
  optionInput.type = "text";
  optionInput.className = "form-control";
  optionInput.placeholder = "Enter option";
  optionDiv.appendChild(optionInput);

  // 创建删除选项按钮的容器
  const deleteButtonSpan = document.createElement("span");
  deleteButtonSpan.className = "input-group-btn"; // Bootstrap 3 使用 input-group-btn
  optionDiv.appendChild(deleteButtonSpan);

  // 创建删除选项按钮
  const deleteButton = document.createElement("button");
  deleteButton.className = "btn btn-danger";
  deleteButton.textContent = "Delete";
  deleteButton.onclick = function () {
    optionList.removeChild(optionDiv);
    updateOptionIndices(optionList);
  };
  deleteButtonSpan.appendChild(deleteButton); // 将按钮添加到其容器中

  optionList.appendChild(optionDiv);

  // 更新选项序号
  updateOptionIndices(optionList);
}

//更新选项序号
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

//更新问题序号
function updateQuestionIndices(pollContainer) {
  const questions = pollContainer.getElementsByClassName("questionDiv");
  for (let i = 0; i < questions.length; i++) {
    // 更新问题的序号
    const questionLabel = questions[i].getElementsByTagName("span")[0];
    questionLabel.textContent = i + 1 + ". ";

    // 更新该问题下的所有选项的序号
    const optionList = questions[i].lastElementChild.previousElementSibling;
    // 根据当前的 DOM 结构，optionList 应该是 questionDiv 的最后一个子元素的前一个子元素
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
