const { MongoClient } = require('mongodb');
const MONGO_URL = 'mongodb://localhost:27017';
const DATABASE_NAME = 'account-db';

async function main() {
    const client = new MongoClient(MONGO_URL);
    await client.connect();
    console.log('Connected to MongoDB successfully');

    const db = client.db(DATABASE_NAME);
    const users = db.collection('users');
    console.log("number of members:", await users.countDocuments());
        
    await client.close();
}

main().catch(console.error);
