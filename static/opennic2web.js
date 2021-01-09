// NB This file is not used, but directly copy-pasted into templates/banner.xml

var o2w_hide_message, o2w_show_message;

(function(){

// Implement show/hide banner

msgElt = document.getElementById('o2w-banner');
hideText = document.getElementById('o2w-hide-banner-text');
showText = document.getElementById('o2w-show-banner-text');

o2w_hide_message = function () {
	sessionStorage.setItem('o2w-hide-message', '1');
	msgElt.classList.add("o2w-hidden");
	hideText.classList.add('o2w-hidden');
	showText.classList.remove('o2w-hidden');
};

o2w_show_message = function () {
	sessionStorage.setItem('o2w-hide-message', '');
	msgElt.classList.remove('o2w-hidden');
	showText.classList.add('o2w-hidden');
	hideText.classList.remove('o2w-hidden');
};

let hide_banner = sessionStorage.getItem('o2w-hide-message');
if (hide_banner) {
	o2w_hide_message();
}

}());
