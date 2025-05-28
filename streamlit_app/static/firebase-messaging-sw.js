// static/firebase-messaging-sw.js
importScripts('https://www.gstatic.com/firebasejs/9.x/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/9.x/firebase-messaging.js');

firebase.initializeApp({
  apiKey: '<API_KEY>',
  authDomain: '<PROJECT_ID>.firebaseapp.com',
  projectId: '<PROJECT_ID>',
  messagingSenderId: '<SENDER_ID>',
  appId: '<APP_ID>'
});
const messaging = firebase.messaging();

messaging.onBackgroundMessage(payload => {
  self.registration.showNotification(
    payload.notification.title,
    { body: payload.notification.body }
  );
});