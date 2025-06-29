//> using scala 3.7.0
//> using dependency "net.java.dev.jna:jna:5.17.0"
//> using dependency "io.bullet::borer-core:1.16.1"
//> using dependency "io.bullet::borer-derivation:1.16.1"
//> using dependency "org.bouncycastle:bcprov-jdk18on:1.81"

import com.sun.jna.ptr.{IntByReference, PointerByReference}
import com.sun.jna.{Library, Native, Pointer}
import io.bullet.borer.*
import io.bullet.borer.derivation.MapBasedCodecs.*
import io.bullet.borer.derivation.key
import org.bouncycastle.jce.interfaces.{ECPrivateKey, ECPublicKey}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec

import java.nio.file.Paths
import java.security.{KeyFactory, KeyPairGenerator, MessageDigest, SecureRandom, Security, Signature}
import javax.crypto.{KeyAgreement, KeyGenerator, Mac, SecretKey}
import scala.util.Try

val libraryPath =
  val os = System.getProperty("os.name").toLowerCase
  val extension = if os.contains("mac") then ".dylib" else ".so"
  s"target/release/libscal3$extension"

object authentication:
  private object impl:
    private trait AuthenticationLibrary extends Library:
      def scal3_process(ip: Array[Byte], il: Int, op: PointerByReference, ol: IntByReference): Unit
      def scal3_free(ptr: Pointer, len: Int): Unit

    private val library: AuthenticationLibrary =
      val path = Paths.get(libraryPath).toFile.getAbsolutePath
      Native.load(path, classOf[AuthenticationLibrary])

    given AdtEncodingStrategy = AdtEncodingStrategy.flat(typeMemberName = "type")

    sealed trait Request derives Codec
    object Request:
      @key("register") case class Register(mask: Array[Byte], randomness: Array[Byte], provider: Array[Byte])
          extends Request derives Codec
      @key("accept") case class Accept(
          provider: Array[Byte],
          verifierSecret: Array[Byte],
          verifier: Array[Byte],
          device: Array[Byte]
      ) extends Request
          derives Codec
      @key("challenge") case class Challenge(randomness: Array[Byte]) extends Request derives Codec
      @key("authenticate") case class Authenticate(
          mask: Array[Byte],
          randomness: Array[Byte],
          provider: Array[Byte],
          subscriber: Array[Byte],
          verifier: Array[Byte],
          device: Array[Byte],
          challenge: Array[Byte],
          hash: Array[Byte]
      ) extends Request
          derives Codec
      @key("pass") case class Pass(proof: Array[Byte], authentication: Long) extends Request derives Codec
      @key("prove") case class Prove(
          randomness: Array[Byte],
          provider: Array[Byte],
          verifierSecret: Array[Byte],
          verifier: Array[Byte],
          device: Array[Byte],
          hash: Array[Byte],
          passSecret: Array[Byte],
          pass: Array[Byte]
      ) extends Request
          derives Codec
      @key("verify") case class Verify(
          verifier: Array[Byte],
          device: Array[Byte],
          hash: Array[Byte],
          authenticator: Array[Byte],
          proof: Array[Byte],
          client: Array[Byte]
      ) extends Request
          derives Codec

    def invoke[Response](request: Request)(using Decoder[Response]): Try[Response] =
      val input = Cbor.encode(request).toByteArray
      val outputPtr = PointerByReference()
      val outputLen = IntByReference()
      impl.library.scal3_process(input, input.length, outputPtr, outputLen)
      val output =
        try outputPtr.getValue.getByteArray(0, outputLen.getValue)
        finally impl.library.scal3_free(outputPtr.getValue, outputLen.getValue)
      Cbor.decode(output).to[Response].valueTry

  object domain:
    import impl.*

    case class SubscriberState(mask: Array[Byte], randomness: Array[Byte], provider: ECPublicKey)
    case class ProviderState(provider: ECPublicKey, secret: Array[Byte], verifier: Array[Byte], device: ECPublicKey)
    case class Registration(subscriber: Array[Byte], verifier: Array[Byte]) derives Codec
    case class PassResponse(sender: Array[Byte], pass: Array[Byte]) derives Codec
    case class Transcript(authenticator: Array[Byte], proof: Array[Byte], client: Array[Byte]) derives Codec
    object service:
      def register(state: SubscriberState): Registration = invoke[Registration](
        Request.Register(state.mask, state.randomness, state.provider.getQ.getEncoded(true))
      ).get
      def accept(state: ProviderState): Boolean =
        invoke[String](
          Request.Accept(
            state.provider.getQ.getEncoded(true),
            state.secret,
            state.verifier,
            state.device.getQ.getEncoded(true)
          )
        ).get == "accepted"
      def challenge(randomness: Array[Byte]): Array[Byte] = {
        case class Response(challenge: Array[Byte]) derives Codec
        invoke[Response](Request.Challenge(randomness)).get.challenge
      }
      def authenticate(
          state: SubscriberState,
          registration: Registration,
          device: ECPublicKey,
          challenge: Array[Byte],
          hash: Array[Byte]
      ): (Array[Byte], Array[Byte] => PassResponse) = {
        case class AuthenticateResponse(digest: Array[Byte], authentication: Long) derives Codec
        val response = invoke[AuthenticateResponse](
          Request.Authenticate(
            state.mask,
            state.randomness,
            state.provider.getQ.getEncoded(true),
            registration.subscriber,
            registration.verifier,
            device.getQ.getEncoded(true),
            challenge,
            hash
          )
        ).get
        def pass(proof: Array[Byte]): PassResponse =
          invoke[PassResponse](Request.Pass(proof, response.authentication)).get
        (response.digest, pass)
      }
      def prove(
          randomness: Array[Byte],
          state: ProviderState,
          hash: Array[Byte],
          passSecret: Array[Byte],
          pass: Array[Byte]
      ): Transcript =
        invoke[Transcript](
          Request.Prove(
            randomness,
            state.provider.getQ.getEncoded(true),
            state.secret,
            state.verifier,
            state.device.getQ.getEncoded(true),
            hash,
            passSecret,
            pass
          )
        ).get
      def verify(verifier: Array[Byte], device: ECPublicKey, hash: Array[Byte], transcript: Transcript): Boolean =
        invoke[String](
          Request.Verify(
            verifier,
            device.getQ.getEncoded(true),
            hash,
            transcript.authenticator,
            transcript.proof,
            transcript.client
          )
        ).get == "verified"

object crypto:
  object domain:
    def generateRandomness(): Array[Byte] = {
      val randomness = Array.ofDim[Byte](32)
      SecureRandom().nextBytes(randomness)
      randomness
    }

    case class HmacSha256Key(k: SecretKey):
      def hmac(msg: Array[Byte]): Array[Byte] =
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(k)
        mac.doFinal(msg)
    object HmacSha256Key:
      def generate(): HmacSha256Key =
        val generator = KeyGenerator.getInstance("HmacSHA256")
        generator.init(256)
        HmacSha256Key(generator.generateKey())

    case class P256Key(sk: ECPrivateKey, pk: ECPublicKey):
      def ecdh(pk: Array[Byte]): Array[Byte] =
        val params = sk.getParameters
        val curve = params.getCurve
        val point = curve.decodePoint(pk)
        val spec = ECPublicKeySpec(point, params)
        val factory = KeyFactory.getInstance("EC", "BC")
        val other = factory.generatePublic(spec)
        val agreement = KeyAgreement.getInstance("ECDH", "BC")
        agreement.init(sk)
        agreement.doPhase(other, true)
        agreement.generateSecret()
      def ecdsa(digest: Array[Byte]): Array[Byte] =
        val signature = Signature.getInstance("NONEwithECDSAinP1363format")
        signature.initSign(sk)
        signature.update(digest)
        signature.sign()

    object P256Key:
      def generate(): P256Key =
        val generator = KeyPairGenerator.getInstance("EC", "BC")
        generator.initialize(256)
        val pair = generator.generateKeyPair()
        P256Key(pair.getPrivate.asInstanceOf[ECPrivateKey], pair.getPublic.asInstanceOf[ECPublicKey])

    case class SecureArea(ec: P256Key, secret: HmacSha256Key)

    def sha256(msg: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-256").digest(msg)

@main def main(): Unit = {
  import authentication.domain.*, crypto.domain.*

  Security.addProvider(BouncyCastleProvider())

  val provider = SecureArea(P256Key.generate(), HmacSha256Key.generate())
  val device = SecureArea(P256Key.generate(), HmacSha256Key.generate())

  val subscriberState = SubscriberState(device.secret.hmac("123456".getBytes), generateRandomness(), provider.ec.pk)
  val registration = service.register(subscriberState)
  val providerState =
    ProviderState(provider.ec.pk, provider.ec.ecdh(registration.subscriber), registration.verifier, device.ec.pk)
  assert(service.accept(providerState))

  val challengeData = """{"nonce":"123456","timestamp":"1748886705"}""".getBytes
  val challenge = service.challenge(provider.secret.hmac(challengeData))
  val clientData = """{"operation":"log-in","session":"68c9eeeddfa5fb50"}""".getBytes
  val (digest, pass) = service.authenticate(subscriberState, registration, device.ec.pk, challenge, sha256(clientData))
  val proof = device.ec.ecdsa(digest)
  val result = pass(proof)
  val transcript = service.prove(
    provider.secret.hmac(challengeData),
    providerState,
    sha256(clientData),
    provider.ec.ecdh(result.sender),
    result.pass
  )

  assert(service.verify(registration.verifier, device.ec.pk, sha256(clientData), transcript))

  println("Demo completed successfully")
}
