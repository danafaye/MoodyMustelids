from pathlib import Path

ROOT=Path(__file__).resolve().parent
stage=(ROOT/'instructor_youtube'/'youtube_stage.py').read_bytes()
key=b'\x13\x37\xc0\xde'
encoded=bytes(v ^ key[i%4] for i,v in enumerate(stage))
(ROOT/'youtube_stage.h').write_text('/* Generated benign Python stage, XOR encoded. */\n'
    +'static const unsigned char GF_YT_STAGE[] = {\n'
    +',\n'.join(','.join('0x%02x'%v for v in encoded[i:i+16]) for i in range(0,len(encoded),16))
    +'\n};\n')
