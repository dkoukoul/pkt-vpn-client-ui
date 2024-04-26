var selectedServer = null;

function selectServerAndToggleDivs(serverItem) {
    selectedServer = serverItem;
    var inputs = serverItem.querySelectorAll('input[type="hidden"]');

    var selectedServerDiv = document.getElementById('selectedServer');
    selectedServerDiv.querySelector('img').src = serverItem.querySelector('img').src;
    selectedServerDiv.querySelector('input[type=hidden]').value = inputs[0].value;
    selectedServerDiv.querySelector('input[type=hidden]:nth-of-type(2)').value = inputs[1].value;
    selectedServerDiv.querySelector('span').textContent = serverItem.querySelector('span').textContent;
    toggleDivs();
}

function toggleDivs() {
    var mainDiv = document.getElementById('main');
    var serverList = document.getElementById('vpnServers');

    if (mainDiv.style.display !== 'none') {
        mainDiv.style.display = 'none';
        serverList.style.display = 'block';
    } else {
        mainDiv.style.display = 'flex';
        serverList.style.display = 'none';
    }
}

function showNotification(type, message) {
    var notificationDiv = document.getElementById('notification');
    notificationDiv.className = 'notification ' + type;
    notificationDiv.textContent = message;
    notificationDiv.classList.remove('hidden');
    setTimeout(function() {
        notificationDiv.classList.add('hidden');
    }, 2500);
}

function showVPNStatus(type, message) {
    var statusDiv = document.getElementById('status');
    // statusDiv.className = 'status ' + type;
    statusDiv.textContent = message;
    setTimeout(function() {
        statusDiv.textContent = '';
    }, 1200);
}

function connectToVpn() {
    var serverItem = document.querySelector('.server-item.selected');

    if (connectButton.classList.contains('connected')) {
        fetch('/disconnect')
        disconnectedServer();
        connectButton.classList.remove('connected');
    } else if (!serverItem) {
        showNotification('error', 'Please select a VPN server')
        return;
    } else {
        var publicKey = selectedServer.querySelector('input[type=hidden]').value;
        var publicIP = selectedServer.querySelector('input[type=hidden]:nth-of-type(2)').value;
        var vpnName = selectedServer.querySelector('span').textContent;
        fetch('/connect?publicKey=' + publicKey + '&publicIP=' + publicIP + '&vpnName='+ vpnName);
        connectButton.classList.add('connected');
    }
}

// Get all server items
var serverItems = document.querySelectorAll('.server-item');

// Get the connect button
var connectButton = document.getElementById('connectButton');

// Add event listener to each server item
serverItems.forEach(function(item) {
    item.addEventListener('click', function() {
        // Remove the selected class from all server items
        serverItems.forEach(function(i) {
            i.classList.remove('selected');
        });
        this.classList.add('selected');
    });
});

var socket = new WebSocket("ws://localhost:8080/ws");

socket.onmessage = function(event) {
    var notification = JSON.parse(event.data);
    progressConnecting = 100;
    alert(notification.message);
    if (notification.message === 'Connecting to VPN Server...') {
        alert('100%');
        progressBar.style.width = progressConnecting+'%';
    } else if (notification.message === 'VPN Connected' && notification.type === 'success') {
        progressBar.style.width = '0';
        connectedServer();
    } else if (notification.type === 'error'){
        progressBar.style.width = '0';
        connectButton.classList.remove('connected');
    } else {
        progressConnecting -= 20;
        alert(progressConnecting);
        progressBar.style.width = progressConnecting+'%';
    }
    showNotification(notification.type, notification.message);
};

function connectedServer() {
    var serverItem = document.querySelector('.server-item.selected');
    if (serverItem) {
        serverItem.classList.remove('selected');
        serverItem.classList.add('connected');
    }
    var counter = 0;
    
    var intervalId = setInterval(function() {
        counter++;
        var hours = Math.floor(counter / 3600);
        var minutes = Math.floor((counter % 3600) / 60);
        var seconds = counter % 60;

        var timeString = (hours > 0 ? hours + " hour(s), " : "") +
                        (minutes > 0 ? minutes + " minute(s), " : "") +
                        seconds + " second(s)";

        showVPNStatus("connected", "Connected for " + timeString);
    }, 1000);
}

function disconnectedServer() {
    var serverItem = document.querySelector('.server-item.connected');
    if (serverItem) {
        serverItem.classList.remove('connected');
    }
}

var selectedServer = document.querySelector('.server-item[selected="true"]');
if (selectedServer) {
    var inputs = selectedServer.querySelectorAll('input[type="hidden"]');

    var selectedServerDiv = document.getElementById('selectedServer');
    selectedServerDiv.querySelector('img').src = selectedServer.querySelector('img').src;
    selectedServerDiv.querySelector('input[type=hidden]').value = inputs[0].value;
    selectedServerDiv.querySelector('input[type=hidden]:nth-of-type(2)').value = inputs[1].value;
    selectedServerDiv.querySelector('span').textContent = selectedServer.querySelector('span').textContent;
    selectedServerDiv.classList.add('selected');
} 
