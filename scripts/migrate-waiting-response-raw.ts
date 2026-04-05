import mongoose from 'mongoose';
import * as dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.join(__dirname, '../.env') });

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error('DATABASE_URL not found in environment');
    process.exit(1);
  }

  console.log('--- Migrating WAITING_FOR_RESPONSE disputes to UNDER_REVIEW (Direct MongoDB update) ---');
  
  try {
    await mongoose.connect(url);
    const db = mongoose.connection.db;
    const collection = db!.collection('disputes');
    
    const count = await collection.countDocuments({ status: 'WAITING_FOR_RESPONSE' });
    
    if (count === 0) {
      console.log('No WAITING_FOR_RESPONSE disputes found. Skipping migration.');
    } else {
      const result = await collection.updateMany(
        { status: 'WAITING_FOR_RESPONSE' },
        { $set: { status: 'UNDER_REVIEW' } }
      );
      console.log(`Successfully migrated ${result.modifiedCount} disputes.`);
    }
  } catch (err) {
    console.error('Migration failed:', err);
  } finally {
    await mongoose.disconnect();
  }
}

main();
