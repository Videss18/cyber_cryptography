"""
Simulador Criptografico Educativo - Practica de Criptografia
Jesus Antonio Martinez Benavides
Descripcion: Aplicacion interactiva para demostrar primitivas
criptograficas (sin llaves, sim+etricas, asimatricas) y
simulaciones de ataques con los roles de Alice, Bob y Eve.
"""

import streamlit as st
import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Configuracion inicial de la interfaz
st.set_page_config(
    page_title="Laboratorio Criptográfico : Alice, Bob & Eve",
    layout="wide"
)

# Estilo visual limpio y sobrio
st.markdown("""
    <style>
    .main { background-color: #f8f9fa; }
    .stAlert { border-radius: 6px; }
    </style>
""", unsafe_allow_html=True)

st.title("Simulador Criptografico Educativo")
st.markdown("Plataforma interactiva para el analisis de mecanismos criptograficos y evaluacion de seguridad frente a atacantes activos.")

# Menu lateral estructurado segun los requerimientos de la practica
st.sidebar.markdown("### Menu Principal")
categoria = st.sidebar.selectbox("Seleccione el apartado:", [
    "1. Cifrados sin uso de llaves (Hash & Esponja)",
    "2. Cifrados Simetricos (AES & HMAC)",
    "3. Cifrados Asimetricos y PKI (RSA)",
    "4. Laboratorio de Ataques (Eve)"
])

# PUNTO 1: SIN LLAVES
if categoria == "1. Cifrados sin uso de llaves (Hash & Esponja)":
    st.header("Cifrados sin uso de llaves: Funciones Hash y Esponja")
    st.write("Las funciones hash garantizan **integridad** y generan huellas digitales de longitud fija sin requerir secretos compartidos.")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Alice (Emisor)")
        mensaje_hash = st.text_input("Mensaje de entrada:", "Datos financieros confidenciales 2026")
        algoritmo = st.selectbox("Algoritmo de Hash:", ["SHA-256", "SHA-3 (256 bits)"])
        
        if st.button("Generar Huella Digital"):
            if algoritmo == "SHA-256":
                huella = hashlib.sha256(mensaje_hash.encode()).hexdigest()
            else:
                huella = hashlib.sha3_256(mensaje_hash.encode()).hexdigest()
            
            st.session_state['huella_actual'] = huella
            st.success(f"Huella calculada correctamente:\n`{huella}`")

    with col2:
        st.subheader("Eve (Observador)")
        st.write("Eve puede ver la huella transmitida en el canal publico, pero no puede invertir el hash para recuperar el mensaje original.")
        if 'huella_actual' in st.session_state:
            st.code(f"Canal Publico -> Huella interceptada:\n{st.session_state['huella_actual']}")

# PUNTO 2: SIMETRICOS
elif categoria == "2. Cifrados Simetricos (AES & HMAC)":
    st.header("Cifrados Simetricos y Autenticacion de Mensajes")
    st.write("Utilizan una **unica clave secreta** compartida para cifrar (confidencialidad) y autenticar (integridad).")
    
    # Simulacion de clave simetrica persistente en la sesion
    if 'sym_key' not in st.session_state:
        st.session_state['sym_key'] = os.urandom(32)

    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("### Alice")
        msg_sim = st.text_input("Mensaje plano:", "Transferencia bancaria de $500")
        if st.button("Cifrar con AES-GCM"):
            nonce = os.urandom(12)
            aesgcm = AESGCM(st.session_state['sym_key'])
            ciphertext = aesgcm.encrypt(nonce, msg_sim.encode(), None)
            
            st.session_state['nonce'] = nonce
            st.session_state['ciphertext'] = ciphertext
            st.success("Mensaje cifrado y autenticado.")
            st.code(f"Nonce: {nonce.hex()[:16]}...\nCiphertext: {ciphertext.hex()[:24]}...")

    with col2:
        st.markdown("### Eve (Laboratorio)")
        st.write("Opciones de alteracion en transito:")
        alterar = st.checkbox("Simular alteracion de bits en el ciphertext")
        
    with col3:
        st.markdown("### Bob (Receptor)")
        if st.button("Recibir y Descifrar"):
            if 'ciphertext' in st.session_state:
                try:
                    ciphertext_a_usar = st.session_state['ciphertext']
                    if alterar:
                        # Simulamos alteracion corrompiendo el primer byte
                        ciphertext_a_usar = bytearray(ciphertext_a_usar)
                        ciphertext_a_usar[0] ^= 0xFF
                        ciphertext_a_usar = bytes(ciphertext_a_usar)
                    
                    aesgcm = AESGCM(st.session_state['sym_key'])
                    decrypted = aesgcm.decrypt(st.session_state['nonce'], ciphertext_a_usar, None)
                    st.success(f"Mensaje aceptado\nTexto: **{decrypted.decode()}**")
                except Exception as e:
                    st.error("**Rechazado:** La etiqueta de autenticacion fallo. Los datos fueron manipulados por Eve o estan corruptos.")
            else:
                st.warning("Alice aun no ha enviado ningun mensaje.")

# PUNTO 3: ASIMETRICOS Y PKI
elif categoria == "3. Cifrados Asimetricos y PKI (RSA)":
    st.header("Cifrado Asimetrico y Firmas Digitales (RSA)")
    st.write("Emplean un par de claves (publica y privada) para garantizar confidencialidad y no repudio.")

    if 'private_key' not in st.session_state:
        st.session_state['private_key'] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        st.session_state['public_key'] = st.session_state['private_key'].public_key()

    msg_asig = st.text_input("Mensaje confidencial para Bob:", "Contraseña de acceso principal")
    
    if st.button("Cifrar con Clave Publica de Bob"):
        ciphertext_rsa = st.session_state['public_key'].encrypt(
            msg_asig.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        st.session_state['ciphertext_rsa'] = ciphertext_rsa
        st.success("Cifrado asimetrico exitoso.")
        st.code(f"Texto cifrado (Hex): {ciphertext_rsa.hex()[:60]}...")

    if 'ciphertext_rsa' in st.session_state and st.button("Bob descifra con su clave privada"):
        plaintext_rsa = st.session_state['private_key'].decrypt(
            st.session_state['ciphertext_rsa'],
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        st.success(f"Bob descifro satisfactoriamente: **{plaintext_rsa.decode()}**")

# PUNTO 4: LABORATORIO DE ATAQUES
elif categoria == "4. Laboratorio de Ataques (Eve)":
    st.header("Simulaciones de Ataques y Vulnerabilidades")
    st.write("Demostracion practica del impacto de una mala implementacion o ausencia de controles de seguridad.")

    tipo_ataque = st.selectbox("Seleccione el escenario de ataque de Eve:", [
        "1. Ataque de Diccionario (Contraseña Debil vs SHA-256)",
        "2. Manipulacion de Cifrado Sin Autenticacion (Modificacion de Bits)"
    ])

    if tipo_ataque == "1. Ataque de Diccionario (Contraseña Debil vs SHA-256)":
        st.subheader("Escenario: Contraseña Debil")
        st.write("Eve intercepta un hash de contraseña y utiliza un diccionario de palabras comunes para adivinarla por fuerza bruta offline.")
        
        pwd_objetivo = st.text_input("Contraseña secreta elegida por el usuario:", type="password", value="123456")
        
        if st.button("Ejecutar Ataque de Diccionario de Eve"):
            hash_objetivo = hashlib.sha256(pwd_objetivo.encode()).hexdigest()
            diccionario = ["admin", "password", "123456", "abc12345", "secreto", "root", "mexico2026"]
            
            st.text("Eve probando el diccionario localmente...")
            encontrado = False
            
            # Mostramos una tabla o lista de los intentos de Eve
            for palabra in diccionario:
                h_test = hashlib.sha256(palabra.encode()).hexdigest()
                if h_test == hash_objetivo:
                    st.error(f"Contraseña rota con exito, Eve encontro la coincidencia exacta: **'{palabra}'**")
                    encontrado = True
                    break
            
            if not encontrado:
                st.info("La contraseña no se encontraba en el diccionario pequeño de Eve (se requeriria un diccionario masivo o fuerza bruta prolongada).")

    elif tipo_ataque == "2. Manipulacion de Cifrado Sin Autenticacion (Modificacion de Bits)":
        st.subheader("Escenario: Falta de Integridad en el Cifrado")
        st.write("Alice envia un mensaje cifrado clasico (sin autenticacion). Eve intercepta el mensaje en el canal y altera un byte antes de que llegue a Bob.")
        
        mensaje_original = "Pagar $100 a Alice"
        st.info(f"Mensaje original de Alice: **'{mensaje_original}'**")
        
        # Botones de accion para simular el laboratorio de Eve
        col_eve1, col_eve2 = st.columns(2)
        
        with col_eve1:
            if st.button("Eve altera los bytes en tránsito"):
                st.session_state['eve_manipulado'] = True
                st.warning("Eve ha modificado sigilosamente los bits del texto cifrado en el canal.")
        
        with col_eve2:
            if st.button("Bob recibe e intenta procesar el mensaje"):
                if st.session_state.get('eve_manipulado', False):
                    st.error("**Sin autenticacion (Cifrado inseguro):** Bob descifra el mensaje pero este llega alterado o corrupto (ej. 'Pagar $900 a Alice'), y Bob **no detecta** que Eve lo manipulo")
                else:
                    st.success("El mensaje llego intacto porque Eve no ha realizado ninguna modificacion.")