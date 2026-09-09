/**
 * GEOGRAPHY EDU - FIREBASE CONFIGURATION
 * High School Help Kit Project
 * 
 * Firebase Firestore replaces localStorage for cloud-based,
 * real-time data synchronization across all users and devices.
 */

// Firebase Configuration
const firebaseConfig = {
  apiKey: "AIzaSyAs1LEj2WXO-6MvS7v2uWg5nPzVsqjbVf0",
  authDomain: "crud-3fd86.firebaseapp.com",
  databaseURL: "https://crud-3fd86-default-rtdb.firebaseio.com",
  projectId: "crud-3fd86",
  storageBucket: "crud-3fd86.firebasestorage.app",
  messagingSenderId: "663063195093",
  appId: "1:663063195093:web:5d892cb09a9d2016c7e15c",
  measurementId: "G-579FGCK6TP"
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
