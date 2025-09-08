document.addEventListener("DOMContentLoaded", function () {
    const storedUsername = sessionStorage.getItem("username");

    // Global navigation check
    document.querySelectorAll('a[href^="/"]').forEach(anchor => {
        anchor.addEventListener('click', function (event) {
            const href = anchor.getAttribute('href');
            if (href !== '/' && !storedUsername) {
                event.preventDefault();
                window.location.href = "/login";
            }
        });
    });
});