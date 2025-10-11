// loadtest.js
const admin = require('firebase-admin');

// IMPORTANT: This tells the script to talk to your LOCAL emulator, not the live database
process.env.FIRESTORE_EMULATOR_HOST = 'localhost:8080';

admin.initializeApp({ projectId: 'your-firebase-project-id' }); // Replace with your actual project ID
const db = admin.firestore();

const FROM_LOCATION = 'makumbura';
const TO_LOCATION = 'galle';
const DAY_OF_WEEK = 'Monday'; // Example day

async function runSearch() {
  try {
    const snapshot = await db.collection('buses')
      .where('availability', 'array-contains', DAY_OF_WEEK)
      .get();
    
    // This part simulates the client-side filtering
    const results = snapshot.docs.filter(doc => {
        const bus = doc.data();
        const fromMatch = (bus.departsFrom.toLowerCase() === FROM_LOCATION) || (bus.expresswayEntrance.toLowerCase() === FROM_LOCATION);
        const toMatch = (bus.arrivesAt.toLowerCase() === TO_LOCATION) || (bus.expresswayExit.toLowerCase() === TO_LOCATION);
        return fromMatch && toMatch;
    });
    // console.log(`Found ${results.length} buses for one user.`);
  } catch (error)
 {
    console.error("A search query failed:", error.message);
  }
}

async function startLoadTest() {
  console.log("Starting load test...");
  const totalRequests = 100; // Simulate 100 users
  const durationSeconds = 10;
  const requestsPerSecond = totalRequests / durationSeconds;

  const promises = [];

  const interval = setInterval(() => {
    for (let i = 0; i < requestsPerSecond; i++) {
        if (promises.length < totalRequests) {
            promises.push(runSearch());
        }
    }
    if (promises.length >= totalRequests) {
      clearInterval(interval);
      Promise.all(promises).then(() => {
        console.log(`Load test finished. ${totalRequests} searches completed.`);
        process.exit(0);
      });
    }
  }, 1000);
}

startLoadTest();