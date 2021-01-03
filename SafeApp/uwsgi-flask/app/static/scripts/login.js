function forgotPassword() {
    var txt = '';
    var name = prompt("Please enter your name:");
    if (name == null || name == "") {
        txt = "Cancelled.";
    } else {
        fetch(`https://localhost/email/${name}`).
            then(resp => {
                if (resp.ok) {
                    return resp.json()
                } else {
                    throw new Error('dupa')
                }
            }).
            then(data => alert(`Email with instruction was sent to ${data.email}. If you didn't ask for password reset, just ignore this information.`)).
            catch(() => alert(`No user with username '${name}' registered.`))
    }
}
