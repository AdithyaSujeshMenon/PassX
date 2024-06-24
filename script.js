function maskPassword(pass){
    let str = ""
    for (let index = 0; index < pass.length; index++) {
        str  += "*"
    }
    return str
}


// Simple salt generation function (for demonstration purposes)
function generateSalt() {
    return CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
}

// Function to hash password with salt
function hashPassword(password, salt) {
    return CryptoJS.PBKDF2(password, salt, { keySize: 512/32, iterations: 10000 }).toString();
}



// Function to encrypt data
function encryptData(data, key) {
    return CryptoJS.AES.encrypt(data, key).toString();
}

// Function to decrypt data
function decryptData(ciphertext, key) {
    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}

function copyText(txt, website) {
    const masterKeyInput = prompt("Enter your master key to copy the information:");
    const storedMasterKey = localStorage.getItem("masterKey");
    const storedSalt = localStorage.getItem("masterKeySalt");

    if (hashPassword(masterKeyInput, storedSalt) === storedMasterKey) {
        navigator.clipboard.writeText(txt).then(
            () => {
                document.getElementById("alert").style.display = "inline";
                setTimeout(() => {
                    document.getElementById("alert").style.display = "none";
                }, 2000);
            },
            () => {
                alert("Clipboard copying failed");
            }
        );
    } else {
        alert("Incorrect master key!");
    }
}

const deletePassword = (website) => {
    const masterKeyInput = prompt("Enter your master key to delete the password:");
    const storedMasterKey = localStorage.getItem("masterKey");
    const storedSalt = localStorage.getItem("masterKeySalt");

    if (hashPassword(masterKeyInput, storedSalt) === storedMasterKey) {
        let data = localStorage.getItem("passwords");
        let arr = JSON.parse(data);
        arrUpdated = arr.filter((e) => {
            return e.website != website;
        });
        localStorage.setItem("passwords", JSON.stringify(arrUpdated));
        alert(`Successfully deleted ${website}'s password`);
        showPasswords();
    } else {
        alert("Incorrect master key!");
    }
};

const showPasswords = () => {
    let tb = document.querySelector("table");
    let data = localStorage.getItem("passwords");
    if (data == null || JSON.parse(data).length == 0) {
        tb.innerHTML = "No Data To Show";
    } else {
        tb.innerHTML = `<tr>
        <th>Website</th>
        <th>Username</th>
        <th>Password</th>
        <th>Delete</th>
    </tr>`;
        let arr = JSON.parse(data);
        let str = "";
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            str += `<tr>
    <td>${element.website} <img onclick="copyText('${element.website}', '${element.website}')" src="./copy.svg" alt="Copy Button" width="10" height="10">
    </td>
    <td>${element.username} <img onclick="copyText('${element.username}', '${element.website}')" src="./copy.svg" alt="Copy Button" width="10" height="10">
    </td>
    <td><span class="password" data-website="${element.website}">${maskPassword(element.password)}</span> <img onclick="copyPassword('${element.website}')" src="./copy.svg" alt="Copy Button" width="10" height="10">
    </td>
    <td><button class="btnsm" onclick="deletePassword('${element.website}')">Delete</button></td>
        </tr>`;
        }
        tb.innerHTML += str;

        // Add click event to show password
        document.querySelectorAll('.password').forEach(span => {
            span.addEventListener('click', function() {
                const website = this.getAttribute('data-website');
                showRealPassword(website, this);
            });
        });
    }
};

// Function to show real password after master key verification
function showRealPassword(website, element) {
    const masterKeyInput = prompt("Enter your master key to view the password:");
    const storedMasterKey = localStorage.getItem("masterKey");
    const storedSalt = localStorage.getItem("masterKeySalt");

    if (hashPassword(masterKeyInput, storedSalt) === storedMasterKey) {
        const passwords = JSON.parse(localStorage.getItem("passwords"));
        const passwordEntry = passwords.find(p => p.website === website);
        
        if (passwordEntry) {
            const decryptedPassword = decryptData(passwordEntry.password, masterKeyInput);
            element.textContent = decryptedPassword;
            setTimeout(() => {
                element.textContent = maskPassword(decryptedPassword);
            }, 30000);
        }
    } else {
        alert("Incorrect master key!");
    }
}

function copyPassword(website) {
    const masterKeyInput = prompt("Enter your master key to copy the password:");
    const storedMasterKey = localStorage.getItem("masterKey");
    const storedSalt = localStorage.getItem("masterKeySalt");

    if (hashPassword(masterKeyInput, storedSalt) === storedMasterKey) {
        const passwords = JSON.parse(localStorage.getItem("passwords"));
        const passwordEntry = passwords.find(p => p.website === website);
        
        if (passwordEntry) {
            const decryptedPassword = decryptData(passwordEntry.password, masterKeyInput);
            copyText(decryptedPassword, website);
        }
    } else {
        alert("Incorrect master key!");
    }
}

// Function to handle login
function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById("loginUsername").value;
    const password = document.getElementById("loginPassword").value;

    if (username === "admin" && password === "admin123") {
        localStorage.setItem("isLoggedIn", "true");
        document.getElementById("login-screen").style.display = "none";
        document.getElementById("password-manager").style.display = "block";
        document.querySelector(".logo").textContent = "Log off";
        if (!localStorage.getItem("masterKey")) {
            promptForMasterKey();
        } else {
            showPasswords();
        }
    } else {
        alert("Invalid username or password");
    }
}

// Function to prompt for master key creation
function promptForMasterKey() {
    const masterKey = prompt("Create your master key:");
    const salt = generateSalt();
    const hashedMasterKey = hashPassword(masterKey, salt);
    localStorage.setItem("masterKey", hashedMasterKey);
    localStorage.setItem("masterKeySalt", salt);
    alert("Master key created successfully!");
    showPasswords();
}

// Function to handle password addition
function handleAddPassword(e) {
    e.preventDefault();
    const website = document.getElementById("website").value;
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    const masterKey = prompt("Enter your master key to add the password:");
    const storedMasterKey = localStorage.getItem("masterKey");
    const storedSalt = localStorage.getItem("masterKeySalt");

    if (hashPassword(masterKey, storedSalt) === storedMasterKey) {
        let passwords = JSON.parse(localStorage.getItem("passwords")) || [];
        const encryptedPassword = encryptData(password, masterKey);
        passwords.push({ website, username, password: encryptedPassword });
        localStorage.setItem("passwords", JSON.stringify(passwords));

        alert("Password Saved");
        showPasswords();
        e.target.reset();
    } else {
        alert("Incorrect master key!");
    }
}

// Function to handle log off
function handleLogOff() {
    if (confirm("Logging off will delete all your data permanently. Are you sure?")) {
        localStorage.clear();
        window.location.reload();
    }
}

// Event Listeners
document.getElementById("loginForm").addEventListener("submit", handleLogin);
document.getElementById("addPasswordForm").addEventListener("submit", handleAddPassword);
document.querySelector(".logo").addEventListener("click", handleLogOff);

// Check if user is logged in
if (localStorage.getItem("isLoggedIn") === "true") {
    document.getElementById("login-screen").style.display = "none";
    document.getElementById("password-manager").style.display = "block";
    document.querySelector(".logo").textContent = "Logoff";
    showPasswords();
                                }
