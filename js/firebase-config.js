/**
 * GEOGRAPHY EDU - FIREBASE CONFIGURATION
 * High School Help Kit Project
 * 
 * Firebase Firestore replaces localStorage for cloud-based,
 * real-time data synchronization across all users and devices.
 */

// Firebase Configuration — doc tu js/env-config.js (sinh boi
// tools/generate_env_config.js dua tren file .env, xem README/khong commit
// gia tri that len Git). Chay "npm run build" sau khi doi .env.
if (!window.__ENV__) {
  console.error("[Firebase] Thieu js/env-config.js! Hay chay 'npm run build' (hoac 'node tools/generate_env_config.js') truoc khi mo trang.");
}
const _ENV = window.__ENV__ || {};

const firebaseConfig = {
  apiKey: _ENV.FIREBASE_API_KEY,
  authDomain: _ENV.FIREBASE_AUTH_DOMAIN,
  databaseURL: _ENV.FIREBASE_DATABASE_URL,
  projectId: _ENV.FIREBASE_PROJECT_ID,
  storageBucket: _ENV.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: _ENV.FIREBASE_MESSAGING_SENDER_ID,
  appId: _ENV.FIREBASE_APP_ID,
  measurementId: _ENV.FIREBASE_MEASUREMENT_ID
};

// Initialize Firebase
const firebaseApp = firebase.initializeApp(firebaseConfig);

// Initialize Firestore
const db = firebase.firestore();

// Initialize Firebase Authentication + Google Provider
const auth = firebase.auth();
const googleProvider = new firebase.auth.GoogleAuthProvider();
// Luôn hiển thị popup chọn tài khoản Google
googleProvider.setCustomParameters({ prompt: 'select_account' });

// Initialize Firebase Cloud Storage
let storage = null;
try {
  if (firebase.storage) {
    storage = firebase.storage();
  }
} catch (storageErr) {
  console.warn("[Firebase Storage] Storage init notice:", storageErr);
}

// Initialize Firebase Analytics
let analytics = null;
try {
  if (firebase.analytics) {
    analytics = firebase.analytics();
  }
} catch (analyticsErr) {
  console.warn("[Firebase Analytics] Analytics init notice:", analyticsErr);
}

// Expose globally
window.firebaseApp = firebaseApp;
window.db = db;
window.auth = auth;
window.googleProvider = googleProvider;
window.storage = storage;
window.analytics = analytics;

console.log("[Firebase] Initialized successfully — Project:", firebaseConfig.projectId);
