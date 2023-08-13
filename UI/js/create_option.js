function addQuestionField() {
    const pollContainer = document.getElementById('pollContainer');

    const questionNumber = pollContainer.getElementsByClassName('questionDiv').length + 1; // 获取当前的问题数

    // 创建新的问题div
    const questionDiv = document.createElement('div');
    questionDiv.className = 'questionDiv';

    const questionLabel = document.createElement('span');
    questionLabel.textContent = questionNumber + ". ";
    questionDiv.appendChild(questionLabel);

    // 创建一个包装div用于问题输入和删除按钮
    const questionInputGroup = document.createElement('div');
    questionInputGroup.className = 'input-group input-spacing';
    questionDiv.appendChild(questionInputGroup);

    // 创建问题输入框
    const questionInput = document.createElement('input');
    questionInput.type = 'text';
    questionInput.className = 'form-control';
    questionInput.placeholder = 'Enter question';
    questionInputGroup.appendChild(questionInput);

    // 创建删除问题按钮容器
    const deleteButtonSpan = document.createElement('span');
    deleteButtonSpan.className = 'input-group-btn';
    questionInputGroup.appendChild(deleteButtonSpan);

    // 创建删除问题按钮
    const deleteQuestionButton = document.createElement('button');
    deleteQuestionButton.className = 'btn btn-danger';
    deleteQuestionButton.textContent = 'Delete Question';
    deleteQuestionButton.onclick = function() {
        pollContainer.removeChild(questionDiv);
    };
    deleteButtonSpan.appendChild(deleteQuestionButton);
    
    // 创建选项列表容器
    const optionList = document.createElement('div');
    questionDiv.appendChild(optionList);

    // 创建添加选项按钮
    const addOptionButton = document.createElement('button');
    addOptionButton.type = 'button';
    addOptionButton.className = 'btn btn-secondary input-spacing';
    addOptionButton.textContent = 'Add Option';
    addOptionButton.onclick = function() {
        addOptionField(optionList);
    };
    questionDiv.appendChild(addOptionButton);

    // 将问题div添加到主容器中
    pollContainer.appendChild(questionDiv);
}

function addOptionField(optionList) {
    const optionDiv = document.createElement('div');
    optionDiv.className = 'input-group input-spacing';

    // 创建序号span
    const indexSpan = document.createElement('span');
    indexSpan.className = 'input-group-addon'; // Bootstrap 3 使用 input-group-addon
    optionDiv.appendChild(indexSpan);

    // 创建选项输入框
    const optionInput = document.createElement('input');
    optionInput.type = 'text';
    optionInput.className = 'form-control';
    optionInput.placeholder = 'Enter option';
    optionDiv.appendChild(optionInput);

    // 创建删除选项按钮的容器
    const deleteButtonSpan = document.createElement('span');
    deleteButtonSpan.className = 'input-group-btn'; // Bootstrap 3 使用 input-group-btn
    optionDiv.appendChild(deleteButtonSpan);

    // 创建删除选项按钮
    const deleteButton = document.createElement('button');
    deleteButton.className = 'btn btn-danger';
    deleteButton.textContent = 'Delete';
    deleteButton.onclick = function() {
        optionList.removeChild(optionDiv);
        updateOptionIndices(optionList);
    };
    deleteButtonSpan.appendChild(deleteButton); // 将按钮添加到其容器中

    optionList.appendChild(optionDiv);

    // 更新选项序号
    updateOptionIndices(optionList);
}


function updateOptionIndices(optionList) {
    const questionDiv = optionList.parentElement;
    const pollContainer = document.getElementById('pollContainer');
    const questions = pollContainer.getElementsByClassName('questionDiv');
    let questionIndex = 1;
    for (let i = 0; i < questions.length; i++) {
        if (questions[i] === questionDiv) {
            questionIndex = i + 1;
            break;
        }
    }

    const optionDivs = optionList.getElementsByClassName('input-group');
    for (let i = 0; i < optionDivs.length; i++) {
        const indexSpan = optionDivs[i].getElementsByClassName('input-group-addon')[0];
        indexSpan.textContent = questionIndex + "." + (i + 1);
    }
}

