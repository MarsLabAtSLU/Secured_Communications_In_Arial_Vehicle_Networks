

-> This level of folder(OffBoard) works on master PC or latop simulating an vATC virtual air traffic control
-> Before running the below said python script, please make sure python-charm(crypo library) is installed.
-> If py-charm not installed, do follow instruction from charm-dev folder ( ../../char-dev) that builds from source.
-> Now at this level we running the applciaiton code.

#1. Running abenc_ca_authority.py script will setup and initialises master and public key for once and store Pk & Mk.
    So, make sure to execute this script at being of everything else and once until life of CA authority.

#2. Secondly, execute the abenc_ca_server.py this file will run the server thread that serves client request to share
    Pk and secret key based on the attribute clients presents/sends. So make sure this server is running all-time.
    Specifically make sure to run this server before starting ObBoard code.

#3. Step 2 will compute the Sk secrete key and share it with client over UDP transfer. 

#4. Next execute vocal_cpabe.py script to process speech to text that maps correpsonding attributes based on speech.

Now, we have completed setting up master/OnBoard CA authority.

