const unameField = document.getElementById('username');
const submitButton = document.getElementById('register-btn');

unameField.addEventListener('change', e => {
    fetch(`https://localhost/checklogin/${e.target.value}`)
        .then(resp => resp.status)
        .then(status => {
            if (status == 200 && e.target.value.length > 4) {
                submitButton.removeAttribute('disabled');
            } else {
                submitButton.setAttribute('disabled', true)
            }
        })
})
