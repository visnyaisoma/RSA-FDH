from Crypto.Signature import PKCS1_PSS   
from Crypto.Hash import SHA256          
from Crypto.PublicKey import RSA         

# Állomány aláírása privát kulccsal.
def sign_the_file(filename, private_key_filename):
    
    # Privát kulcs betöltése read binary módban.
    with open(private_key_filename, 'rb') as f:
        private_key = RSA.import_key(f.read())

    # Az aláírandó fájl betöltése read binary módban.
    with open(filename, 'rb') as f:
        file_contents = f.read()

    # A fájl hash értékének kiszámítása.
    hash = SHA256.new(file_contents)

    # Hash érték kibővítése az RSA-FDH algoritmus szerint PKCS szabvány használatával.
    # Ezzel biztosítjuk, hogy mindig különböző aláírásokat kapjunk.
    padded_hash = PKCS1_PSS.new(private_key).sign(hash)

    # Az RSA-FDH algoritmus által előállított sign_the_file visszaadása.
    return padded_hash

# Állomány ellenőrzése publikus kulccsal.
def verify_file(filename, signature, public_key_filename):
    
    # Publikus kulcs betöltése read binary módban.
    with open(public_key_filename, 'rb') as f:
        public_key = RSA.import_key(f.read())

    # A verifikálandó fájl betöltése read binary módban.
    with open(filename, 'rb') as f:
        file_contents = f.read()

    # A fájl hash értékének kiszámítása.
    hash = SHA256.new(file_contents)

    # Az aláírás ellenőrzése
    try:
        PKCS1_PSS.new(public_key).verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False

# Aláírandó file.
filename = 'example.txt'

# Privát kulcsot tartalmazó file.
private_key_filename = 'private_key.pem'

# Nyilvános kulcsot tartalmazó file.
public_key_filename = 'public_key.pem'

# File aláírása
signature = sign_the_file(filename, private_key_filename)

# Az aláírás elmentése egy .bin kiterjesztésű fájlba. (Bármilyen más formátumban is elmenthető.)
with open('signature.bin', 'wb') as f:
    f.write(signature)

# Az aláírás ellenőrzése.
with open('signature.bin', 'rb') as f:
    signature = f.read()

if verify_file(filename, signature, public_key_filename):
    print("Az aláírás érvényes!")
else:
    print("Az aláírás érvénytelen!")