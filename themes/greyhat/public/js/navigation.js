function myFunction() {
    var x = document.getElementById("myLinks");
    if (x.style.display === "block") {
        x.style.display = "none";
    } else {
        x.style.display = "block";
    }
}

document.addEventListener('DOMContentLoaded', function(){
    document.querySelector(".topnav > .icon").onclick = myFunction;
}, false);
