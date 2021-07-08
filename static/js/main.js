var nav = document.getElementById("nav");
var mn = document.getElementById("menu");

function openNav() {
    nav.style.height = "85%";
    mn.style.color = "transparent";
}

function closeNav() {
    nav.style.height = "0%";
    mn.style.color = "white";
}

function mast() {
    if (nav.style.height == "85%") {
        nav.style.height = "0%";
        mn.style.color = "white";
    }
}

function easter_egg() {
    document.getElementById('lo').style.color = "#dda0dd";
    window.location.href = '/egg';
}

function labour(location) {
    window.location.replace(location);
}

var frame = document.getElementById("frame");
var frame2 = document.getElementById("frame2");
var frame3 = document.getElementById("frame3");
var profile = document.getElementById("profile");
var profile2 = document.getElementById("profile2");
var profile3 = document.getElementById("profile3");

function joy() {
    profile.style.display = "none";
    frame.style.display = "block";
}
function close1() {
    profile.style.display = "block";
    frame.style.display = "none";
}

function wny() {
    profile2.style.display = "none";
    frame2.style.display = "block";
}
function close2() {
    profile2.style.display = "block";
    frame2.style.display = "none";
}

function chr() {
    profile3.style.display = "none";
    frame3.style.display = "block";
}
function close3() {
    profile3.style.display = "block";
    frame3.style.display = "none";
}

var frame4 = document.getElementById("frame4");
var profile4 = document.getElementById("profile4");
function wma() {
    profile4.style.display = "none";
    frame4.style.display = "block";
}
function close4() {
    profile4.style.display = "block";
    frame4.style.display = "none";
}


var li = document.getElementById('login');
var su = document.getElementById('sign_up');
var lc = document.getElementById('log_changer');
var lt = document.getElementById('log_title');

function login() {
    if (li.style.display == "none") {
        li.style.display = "block";
        su.style.display = "none";
        lc.innerHTML = "Sign Up";
        lt.innerHTML = "Login";
    }else {
        li.style.display = "none";
        su.style.display = "block";
        lc.innerHTML = "Login";
        lt.innerHTML = "Sign Up";
    }
}

var req1 = document.getElementById('requester');
var dis1 = document.getElementById('dispatcher');

var popUp = document.getElementById('back');
var bod = document.getElementById('content_hidden');

function boston() {
    if (popUp.style.display == "none") {
        popUp.style.display = "block";
        bod.style.display = "none";
        req1.innerHTML = "Back";
        dis1.style.display = "none";
    }else {
        popUp.style.display = "none";
        bod.style.display = "block";
        req1.innerHTML = "Request";
        dis1.style.display = "flex";
    }
}

var seat = document.getElementById('seat');
var set = document.getElementById('set');

function seattle() {
    if (seat.style.display == "none") {
        seat.style.display = "flex";
        set.style.display = "none";
    }else {
        seat.style.display = "none";
        set.style.display = "block";
    }
}

var loc = document.getElementById('back_loc');

function sergio() {
    if (loc.style.display == "none") {
        loc.style.display = "block";
        bod.style.display = "none";
    }else {
        loc.style.display = "none";
        bod.style.display = "block";
    }
}

var rf = document.getElementById('dispatch');
function dispatch() {
    if (rf.style.display == "none") {
        rf.style.display = "block";
        bod.style.display = "none";
        dis1.innerHTML = "Back";
        req1.style.display = "none";
    }else {
        rf.style.display = "none";
        dis1.innerHTML = "Dispatch";
        bod.style.display = "block";
        req1.style.display = "flex";
    }
}






