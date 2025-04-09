function showLogoutModal() {
    document.getElementById("logout-modal").style.display = "block";
}

function closeLogoutModal() {
    document.getElementById("logout-modal").style.display = "none";
}

function confirmLogout() {
    document.getElementById("logout-modal").style.display = "none";
    window.location.href = "/logout";
}

window.onclick = function(event) {
    const modal = document.getElementById("logout-modal");
    if (event.target === modal) {
        modal.style.display = "none";
    }
};