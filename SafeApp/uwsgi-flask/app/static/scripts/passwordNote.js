const passwordField = document.getElementById('cripted-password');
const usernameField = document.getElementById('shared-username');

const select = document.getElementsByClassName('form-select')[0];

select.addEventListener('change', () => {
    console.log(select.value)
    if (select.value === 'shared') {
        passwordField.setAttribute('disabled', true);
        usernameField.removeAttribute('disabled');
    } else if (select.value === 'protected') {
        usernameField.setAttribute('disabled', true);
        passwordField.removeAttribute('disabled');
    }
    else {
        passwordField.setAttribute('disabled', true);
        usernameField.setAttribute('disabled', true);
    }
})

usernameField.addEventListener('change', e => {
    console.log(e.target.value)
    fetch(`https://localhost/checklogin/${e.target.value}`)
        .then(resp => resp.status)
        .then(status => {
            if (status == 200) {
                usernameField.style.backgroundColor = '#FFA8A8';
            } else {
                usernameField.style.backgroundColor = '#B3FFA8';
            }
        })
})