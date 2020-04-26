package re.indigo.breakthesilence

import java.io.File
import java.util.Properties
import java.util.Base64


fun main(args: Array<String>) {
	val propFile = File(args[0])

	val props = Properties()
	props.load(propFile.reader())

	val silProps = MasterSecretUtil.InputData()

	silProps.passphrase_iterations = props.getProperty("passphrase_iterations")!!.toInt()
	silProps.master_secret = Base64.getDecoder().decode(props.getProperty("master_secret"))
	silProps.mac_salt = Base64.getDecoder().decode(props.getProperty("mac_salt"))
	silProps.encryption_salt = Base64.getDecoder().decode(props.getProperty("encryption_salt"))

	val sec = MasterSecretUtil.getMasterSecret(silProps, "unencrypted")
	println("encryption_key = " + Base64.getEncoder().encodeToString(sec.encryptionKey))
	println("mac_key = " + Base64.getEncoder().encodeToString(sec.macKey))
}
