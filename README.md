# ntlm-pdf-thief

Steal Net-NTLMv2 with a payload in a pdf file. Use the payload or merge it with a real pdf.
Once the pdf is opened, SMB informations are sent. 
You can use it with Metasploit (local or on a VPS through ssh) or with Repsonder to collect all the informations.

Even if a pop-up appear and ask the opener to allow or disallow connection, informations are already sent.
It seems Acrobat will not patch or change this feature. According to reference [1], it should work with other PDF readers. 

# Required packages

- pdfrw
- PyPDF2
- minipdf

# References

- [1] https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/ 
