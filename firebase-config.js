// firebase-config.js - Frontend Firebase Configuration
import { initializeApp } from 'firebase/app';
import { getAuth, connectAuthEmulator } from 'firebase/auth';
import { getFirestore, connectFirestoreEmulator } from 'firebase/firestore';
import { getStorage, connectStorageEmulator } from 'firebase/storage';
import { getAnalytics } from 'firebase/analytics';

// Your web app's Firebase configuration
// Replace with your actual Firebase config
const firebaseConfig = {
  apiKey: "AIzaSyDW6WAqJ4kDumFgdrsR99Xcy4ipH3ePBoY",
  authDomain: "fitai-app-fe8df.firebaseapp.com",
  projectId: "fitai-app-fe8df",
  storageBucket: "fitai-app-fe8df.firebasestorage.app",
  messagingSenderId: "519087526504",
  appId: "1:519087526504:web:6005a09cfc553ed5c421dd"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize Firebase Authentication
export const auth = getAuth(app);

// Initialize Cloud Firestore
export const db = getFirestore(app);

// Initialize Cloud Storage
export const storage = getStorage(app);

// Initialize Analytics (optional)
export const analytics = getAnalytics(app);

// Connect to emulators in development
if (window.location.hostname === 'localhost') {
  console.log('🔧 Connecting to Firebase emulators...');
  
  // Connect to Authentication emulator
  if (!auth._delegate._config.emulator) {
    connectAuthEmulator(auth, "http://localhost:9099", { disableWarnings: true });
  }
  
  // Connect to Firestore emulator
  if (!db._delegate._databaseId.host.includes('localhost')) {
    connectFirestoreEmulator(db, 'localhost', 8080);
  }
  
  // Connect to Storage emulator
  if (!storage._delegate._host.includes('localhost')) {
    connectStorageEmulator(storage, 'localhost', 9199);
  }
}

// Authentication utilities
export const authUtils = {
  // Sign up with email and password
  async signUp(email, password, displayName) {
    try {
      const { createUserWithEmailAndPassword, updateProfile } = await import('firebase/auth');
      
      const userCredential = await createUserWithEmailAndPassword(auth, email, password);
      
      // Update user profile with display name
      await updateProfile(userCredential.user, {
        displayName: displayName
      });
      
      // Send email verification
      const { sendEmailVerification } = await import('firebase/auth');
      await sendEmailVerification(userCredential.user);
      
      return {
        success: true,
        user: userCredential.user,
        message: 'Account created! Please check your email for verification.'
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  },

  // Sign in with email and password
  async signIn(email, password) {
    try {
      const { signInWithEmailAndPassword } = await import('firebase/auth');
      
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      
      // Check if email is verified
      if (!userCredential.user.emailVerified) {
        return {
          success: false,
          error: 'Please verify your email before signing in.'
        };
      }
      
      return {
        success: true,
        user: userCredential.user
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  },

  // Sign out
  async signOut() {
    try {
      const { signOut } = await import('firebase/auth');
      await signOut(auth);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  },

  // Reset password
  async resetPassword(email) {
    try {
      const { sendPasswordResetEmail } = await import('firebase/auth');
      await sendPasswordResetEmail(auth, email);
      return {
        success: true,
        message: 'Password reset email sent!'
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  },

  // Get current user ID token
  async getIdToken() {
    try {
      const user = auth.currentUser;
      if (!user) return null;
      
      return await user.getIdToken();
    } catch (error) {
      console.error('Error getting ID token:', error);
      return null;
    }
  }
};

// Firestore utilities
export const firestoreUtils = {
  // Add document to collection
  async addDocument(collectionName, data) {
    try {
      const { collection, addDoc, serverTimestamp } = await import('firebase/firestore');
      
      const docRef = await addDoc(collection(db, collectionName), {
        ...data,
        createdAt: serverTimestamp()
      });
      
      return { success: true, id: docRef.id };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },

  // Get document by ID
  async getDocument(collectionName, docId) {
    try {
      const { doc, getDoc } = await import('firebase/firestore');
      
      const docRef = doc(db, collectionName, docId);
      const docSnap = await getDoc(docRef);
      
      if (docSnap.exists()) {
        return {
          success: true,
          data: { id: docSnap.id, ...docSnap.data() }
        };
      } else {
        return { success: false, error: 'Document not found' };
      }
    } catch (error) {
      return { success: false, error: error.message };
    }
  },

  // Get collection with optional filtering
  async getCollection(collectionName, filters = []) {
    try {
      const { collection, getDocs, query, where, orderBy, limit } = await import('firebase/firestore');
      
      let q = collection(db, collectionName);
      
      // Apply filters
      filters.forEach(filter => {
        if (filter.type === 'where') {
          q = query(q, where(filter.field, filter.operator, filter.value));
        } else if (filter.type === 'orderBy') {
          q = query(q, orderBy(filter.field, filter.direction || 'asc'));
        } else if (filter.type === 'limit') {
          q = query(q, limit(filter.value));
        }
      });
      
      const querySnapshot = await getDocs(q);
      const documents = [];
      
      querySnapshot.forEach((doc) => {
        documents.push({ id: doc.id, ...doc.data() });
      });
      
      return { success: true, data: documents };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },

  // Update document
  async updateDocument(collectionName, docId, data) {
    try {
      const { doc, updateDoc, serverTimestamp } = await import('firebase/firestore');
      
      const docRef = doc(db, collectionName, docId);
      await updateDoc(docRef, {
        ...data,
        updatedAt: serverTimestamp()
      });
      
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },

  // Delete document
  async deleteDocument(collectionName, docId) {
    try {
      const { doc, deleteDoc } = await import('firebase/firestore');
      
      const docRef = doc(db, collectionName, docId);
      await deleteDoc(docRef);
      
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
};

// Storage utilities
export const storageUtils = {
  // Upload file
  async uploadFile(path, file, metadata = {}) {
    try {
      const { ref, uploadBytesResumable, getDownloadURL } = await import('firebase/storage');
      
      const storageRef = ref(storage, path);
      const uploadTask = uploadBytesResumable(storageRef, file, metadata);
      
      return new Promise((resolve, reject) => {
        uploadTask.on('state_changed',
          (snapshot) => {
            // Progress monitoring
            const progress = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
            console.log(`Upload is ${progress}% done`);
          },
          (error) => {
            reject({ success: false, error: error.message });
          },
          async () => {
            // Upload completed successfully
            try {
              const downloadURL = await getDownloadURL(uploadTask.snapshot.ref);
              resolve({ success: true, downloadURL });
            } catch (error) {
              reject({ success: false, error: error.message });
            }
          }
        );
      });
    } catch (error) {
      return { success: false, error: error.message };
    }
  },

  // Delete file
  async deleteFile(path) {
    try {
      const { ref, deleteObject } = await import('firebase/storage');
      
      const storageRef = ref(storage, path);
      await deleteObject(storageRef);
      
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
};

// Real-time listeners
export const realtimeUtils = {
  // Listen to document changes
  listenToDocument(collectionName, docId, callback) {
    const { doc, onSnapshot } = require('firebase/firestore');
    
    const docRef = doc(db, collectionName, docId);
    
    return onSnapshot(docRef, (docSnap) => {
      if (docSnap.exists()) {
        callback({ id: docSnap.id, ...docSnap.data() });
      } else {
        callback(null);
      }
    });
  },

  // Listen to collection changes
  listenToCollection(collectionName, filters = [], callback) {
    const { collection, query, where, orderBy, onSnapshot } = require('firebase/firestore');
    
    let q = collection(db, collectionName);
    
    filters.forEach(filter => {
      if (filter.type === 'where') {
        q = query(q, where(filter.field, filter.operator, filter.value));
      } else if (filter.type === 'orderBy') {
        q = query(q, orderBy(filter.field, filter.direction || 'asc'));
      }
    });
    
    return onSnapshot(q, (querySnapshot) => {
      const documents = [];
      querySnapshot.forEach((doc) => {
        documents.push({ id: doc.id, ...doc.data() });
      });
      callback(documents);
    });
  }
};

// Export default configuration
export default {
  app,
  auth,
  db,
  storage,
  analytics,
  authUtils,
  firestoreUtils,
  storageUtils,
  realtimeUtils
};
