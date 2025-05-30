// static/firebase-messaging-sw.js
importScripts('https://www.gstatic.com/firebasejs/9.x/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/9.x/firebase-messaging.js');

firebase.initializeApp({
  apiKey: 'AIzaSyATtW92Kmqasqo1AiWMntz-eM4NrqZ2JXw',
  authDomain: 'leveraged-fund-trading-notify.firebaseapp.com',
  projectId: 'leveraged-fund-trading-notify',
  messagingSenderId: '832074947393',
  appId: '1:832074947393:web:e882205f72dae2f4a19fc0'
});
const messaging = firebase.messaging();

messaging.onBackgroundMessage(payload => {
  self.registration.showNotification(
    payload.notification.title,
    { body: payload.notification.body }
  );
});