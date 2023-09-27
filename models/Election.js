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
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },  // can be used to associate the user who created the election
    registeredVoters: [
        { user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } }
    ],
    votes: [
        {
            user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
            selection: String // or any other data type you may need, such as Number
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
        state: Number, // 0: not tallied, 1: provisional tally, 2: final tally
    }
});

/**
 * This function is plaintext provisional tally. Test use only.
 */
electionSchema.statics.provisionalTally = async function (uuid) {
    const Election = mongoose.model('Election');  // Import the Election model

    // Find the corresponding election from the database
    const election = await Election.findOne({ uuid }).exec();

    if (!election) {
        throw new Error('Election not found');
    }

    // Initialize an empty object to store vote counts
    const voteCounts = { Yes: 0, No: 0 };

    // Initialize a variable to store the number of nullified ballots
    let nullifiedVotes = 0;

    // Iterate through each ballot
    for (const vote of election.votes) {
        // Record or update the vote count
        const selection = vote.selection;
        if (voteCounts[selection]) {
            voteCounts[selection]++;
        } else {
            voteCounts[selection] = 1;
        }
    }

    election.result = { voteCounts, nullifiedVotes, state: 1 };
    await election.save();
}

/**
 * This function is plaintext final tally. Test use only.
 */
electionSchema.statics.finalTally = async function (uuid) {
    const Election = mongoose.model('Election');  // Import the Election model

    // Find the corresponding election from the database
    const election = await Election.findOne({ uuid }).exec();

    if (!election) {
        throw new Error('Election not found');
    }

    // Initialize an empty object to store vote counts
    const voteCounts = { Yes: 0, No: 0 };

    // Initialize a variable to store the number of spoiled ballots
    let nullifiedVotes = 0;

    // Iterate through each ballot
    for (const vote of election.votes) {
        const userId = vote.user.toString();  // Convert Mongoose ObjectId to string

        // Check whether this user has nullified the ballot
        const isNullified = election.nullification.some(n => n.user.toString() === userId);

        if (isNullified) {
            nullifiedVotes++;
            continue;  // Skip this nullified ballot
        }

        // Record or update the vote count
        const selection = vote.selection;
        if (voteCounts[selection]) {
            voteCounts[selection]++;
        } else {
            voteCounts[selection] = 1;
        }
    }

    election.result = { voteCounts, nullifiedVotes, state: 2 };
    await election.save();
}

module.exports = mongoose.model('Election', electionSchema);
