const mongoose = require('mongoose');
const uuidv4 = require('uuid').v4;

const electionSchema = new mongoose.Schema({
    uuid: { type: String, default: uuidv4 },
    title: { type: String, required: true, unique: true },
    description: String,
    question: { type: String, required: true },
    email: { type: String, required: true },
    voteStartTime: { type: Date, required: true },
    voteEndTime: { type: Date, required: true },
    nulEndTime: { type: Date, required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },  // 可以用来关联创建选举的用户
    votes: [
        {
            user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
            selection: String // 或其他你需要的数据类型，如Number
        }
    ],
    nullification: [
        {
            user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
        }
    ],
    result: {
        voteCounts: Object,
        nullifiedVotes: Number,
        state: Number, // 0: not tallied，1: provisional tally，2: final tally
    }
});

electionSchema.statics.provisionalTally = async function(uuid) {
    const Election = mongoose.model('Election');  // 导入 Election 模型

    // 从数据库中找到相应的选举
    const election = await Election.findOne({ uuid }).exec();

    if (!election) {
        throw new Error('Election not found');
    }

    // 初始化一个空对象来存储选票计数
    const voteCounts = { Yes: 0, No: 0 };

    // 初始化一个变量来存储作废的选票数量
    let nullifiedVotes = 0;

    // 遍历每一张选票
    for (const vote of election.votes) {
        // 记录或更新选票计数
        const selection = vote.selection;
        if (voteCounts[selection]) {
            voteCounts[selection]++;
        } else {
            voteCounts[selection] = 1;
        }
    }

    // 在这里，voteCounts 对象包含了每个选项的选票计数，
    // nullifiedVotes 变量包含了作废选票的数量。
    // 你可以根据需要进行更多的处理，例如保存结果到数据库，或返回给客户端。

    election.result = { voteCounts, nullifiedVotes, state: 1 };
    await election.save();
}

electionSchema.statics.finalTally = async function(uuid) {
    const Election = mongoose.model('Election');  // 导入 Election 模型

    // 从数据库中找到相应的选举
    const election = await Election.findOne({ uuid }).exec();

    if (!election) {
        throw new Error('Election not found');
    }

    // 初始化一个空对象来存储选票计数
    const voteCounts = { Yes: 0, No: 0 };

    // 初始化一个变量来存储作废的选票数量
    let nullifiedVotes = 0;

    // 遍历每一张选票
    for (const vote of election.votes) {
        const userId = vote.user.toString();  // 把 Mongoose ObjectId 转换为字符串

        // 检查此用户是否作废了选票
        const isNullified = election.nullification.some(n => n.user.toString() === userId);

        if (isNullified) {
            nullifiedVotes++;
            continue;  // 跳过这张作废的选票
        }

        // 记录或更新选票计数
        const selection = vote.selection;
        if (voteCounts[selection]) {
            voteCounts[selection]++;
        } else {
            voteCounts[selection] = 1;
        }
    }

    // 在这里，voteCounts 对象包含了每个选项的选票计数，
    // nullifiedVotes 变量包含了作废选票的数量。
    // 你可以根据需要进行更多的处理，例如保存结果到数据库，或返回给客户端。

    election.result = { voteCounts, nullifiedVotes, state: 2 };
    await election.save();
}

module.exports = mongoose.model('Election', electionSchema);
