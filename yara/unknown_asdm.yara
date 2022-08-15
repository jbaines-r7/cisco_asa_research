import "hash" 

rule Unknown_ASDM_Package {

    meta:
        description = "Unknown ASDM Package"
        author = "Jacob Baines"

    strings:
        $magic = "ASDM IMG"
        $sgz = "pdm.sgz"
        $version = "version.prop"

    condition:
        $magic at 0 and $sgz and $version and
        hash.md5(0, filesize) != "40a57c4e98dc43899832ae20f5b090d4" and
        hash.md5(0, filesize) != "0235ec994fcdb75a2fe026a279af297d" and
        hash.md5(0, filesize) != "622a715e77bdce2d8a839a21ebe3b0a6" and
        hash.md5(0, filesize) != "cad22d44047c658c87eb1b5327c42c16" and
        hash.md5(0, filesize) != "3361688b47d93cb93dd3c0cdd8670e1f" and
        hash.md5(0, filesize) != "faa694cb763197bfeb6e27de90a66dc6" and
        hash.md5(0, filesize) != "9e58de85ad2d4a0b1465b0345899aaa2" and
        hash.md5(0, filesize) != "1d60c88e434fb2473595c7187b1cb434" and
        hash.md5(0, filesize) != "cb0fbea73845749bab553aebc448603b" and
        hash.md5(0, filesize) != "36f86573a148af2b0d89712ab84f0cb3" and
        hash.md5(0, filesize) != "7eba68e65a12ed4da145975b1251062c" and
        hash.md5(0, filesize) != "36ac5d1147baaa963284d15b6726c72c" and
        hash.md5(0, filesize) != "723b897618a1d45bd5549a96f34329aa" and
        hash.md5(0, filesize) != "dd4addd6cbb46f465015c0528d531768" and
        hash.md5(0, filesize) != "77f8b3f90ba0d4748550ba826c25b1d8" and
        hash.md5(0, filesize) != "2e37dbaa2d4299916be644a48cc51c8f" and
        hash.md5(0, filesize) != "0e3f53428bcb4035f60e6076dd6ad308" and
        hash.md5(0, filesize) != "dbba43a22afcffdd0c53fddeac9865f1" and
        hash.md5(0, filesize) != "fac75582056ebb9599d03f1ca354073c" and
        hash.md5(0, filesize) != "33458da82bac90f4695990d5fbd322f9" and
        hash.md5(0, filesize) != "8017973b9bc3a35e2f3609e862614363" and
        hash.md5(0, filesize) != "d503fe1bce1f0b8ca461a033fe8c3dbd" and
        hash.md5(0, filesize) != "9c37497700d5fa15314d1d17e2dbf408" and
        hash.md5(0, filesize) != "8d72cefd69d99a5de42bc56b1b4ca2fc" and
        hash.md5(0, filesize) != "976f4ca376c7d9cb21c3f80006bb212f" and
        hash.md5(0, filesize) != "aca8af8e44e127b88b0ad6bc812ee4a9" and
        hash.md5(0, filesize) != "9aaf024fd30be37d55711f9e5694bdd5" and
        hash.md5(0, filesize) != "cbe0c1fbdccc745eba3a33aebd38dda8" and
        hash.md5(0, filesize) != "030dcdab67333c40028ce7774be6b4dd" and
        hash.md5(0, filesize) != "af7fe78af954facc93f5e1357224483e" and
        hash.md5(0, filesize) != "9b4b3ef5c9a82b43bc84e5dc5006588c" and
        hash.md5(0, filesize) != "0358d136c0c243d16aa8b479594b4c27" and
        hash.md5(0, filesize) != "e58a555d6ac31c2f9400c58f35da4b4b" and
        hash.md5(0, filesize) != "4ae7ad2cd4f4a48f0c19aa5b82da8a61" and
        hash.md5(0, filesize) != "c2da1e1fca930ffca75d954d274b7f53" and
        hash.md5(0, filesize) != "3d567e424bb476f161642f787768f2b6" and
        hash.md5(0, filesize) != "eec67ea0f38aa249b18ef6f4e0667ebe" and
        hash.md5(0, filesize) != "f862f37a5e00ca3fb0a50bcb9ac036d0" and
        hash.md5(0, filesize) != "5783f0ac96e8e1160031a6e770d68151" and
        hash.md5(0, filesize) != "5af12c8c20941d7dcf12c23ecddeb1d9" and 
        hash.md5(0, filesize) != "328607b88063d22d96df2f5ce1d67bee" and
        hash.md5(0, filesize) != "5871d371950e3861c303d351de361f54" and
        hash.md5(0, filesize) != "01ea62bd21adc1d1e7a361cd45279556"
}
