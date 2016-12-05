# SignApk

 * How to Compile:
 * 1. javac SignApk.java
 * 2. Create MANIFEST.MF - ( echo Main-Class: nDasJoWo.SignApk >MANIFEST.MF )
 * 3. Create folder nDasJoWo
 * 4. Move all class(*.class) to folder nDasJoWo
 * 5. jar cvfm SignApk.jar MANIFEST.MF nDasJoWo\*.class
 * 6. java -jar SignApk.jar
 * . 
 *
 
 #### Download ####
 - [SignApk.java](https://raw.githubusercontent.com/ndasjowo/SignApk/master/SignApk.java)
 - [SignApk.jar](https://raw.githubusercontent.com/ndasjowo/SignApk/master/SignApk.jar)
 
 ### License ###
Released under the Apache 2.0 License (the same as Android's [SignApk.java(https://github.com/android/platform_build/blob/master/tools/signapk/SignApk.java)).

 #### Source and Referece ####
 * Source original https://github.com/android/platform_build/blob/master/tools/signapk/SignApk.java
 * Referece: https://github.com/appium/sign/
 
