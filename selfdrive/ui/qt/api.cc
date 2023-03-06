#include "selfdrive/ui/qt/api.h"

#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>

#include <QApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <QNetworkRequest>

#include "common/params.h"
#include "common/util.h"
#include "system/hardware/hw.h"
#include "selfdrive/ui/qt/util.h"

namespace CommaApi {

QByteArray rsa_sign(const QByteArray &data) {
  static std::string key = util::read_file(Path::rsa_file());
  if (key.empty()) {
    qDebug() << "No RSA private key found, please run manager.py or registration.py";
    return {};
  }
  
  auto mem = BIO_new_mem_buf(key.data(), key.size());
  assert(mem);
  EVP_PKEY* rsa_private = nullptr;
  auto dctx = OSSL_DECODER_CTX_new_for_pkey(&rsa_private, "PEM", nullptr, "RSA", OSSL_KEYMGMT_SELECT_KEYPAIR, nullptr, nullptr);
  assert(dctx);
  assert(1 == OSSL_DECODER_from_bio(dctx, mem));
  assert(rsa_private);
 
  auto sig = QByteArray();
  sig.resize(EVP_PKEY_get_size(rsa_private));
 
  auto mdctx = EVP_MD_CTX_create();
  assert(mdctx);
 
  size_t sig_len = sig.size();
  assert(1 == EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, rsa_private));
  assert(1 == EVP_DigestSign(mdctx, (unsigned char*)sig.data(), &sig_len, (unsigned char*)data.data(), data.size()));
  assert(sig_len == sig.size());

  BIO_free(mem); 
  EVP_MD_CTX_destroy(mdctx);
  OSSL_DECODER_CTX_free(dctx);
  EVP_PKEY_free(rsa_private);

  return sig;
}

QString create_jwt(const QJsonObject &payloads, int expiry) {
  QJsonObject header = {{"alg", "RS256"}};

  auto t = QDateTime::currentSecsSinceEpoch();
  QJsonObject payload = {{"identity", getDongleId().value_or("")}, {"nbf", t}, {"iat", t}, {"exp", t + expiry}};
  for (auto it = payloads.begin(); it != payloads.end(); ++it) {
    payload.insert(it.key(), it.value());
  }

  auto b64_opts = QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals;
  QString jwt = QJsonDocument(header).toJson(QJsonDocument::Compact).toBase64(b64_opts) + '.' +
                QJsonDocument(payload).toJson(QJsonDocument::Compact).toBase64(b64_opts);

  auto hash = QCryptographicHash::hash(jwt.toUtf8(), QCryptographicHash::Sha256);
  auto sig = rsa_sign(hash);
  jwt += '.' + sig.toBase64(b64_opts);
  return jwt;
}

}  // namespace CommaApi

HttpRequest::HttpRequest(QObject *parent, bool create_jwt, int timeout) : create_jwt(create_jwt), QObject(parent) {
  networkTimer = new QTimer(this);
  networkTimer->setSingleShot(true);
  networkTimer->setInterval(timeout);
  connect(networkTimer, &QTimer::timeout, this, &HttpRequest::requestTimeout);
}

bool HttpRequest::active() const {
  return reply != nullptr;
}

bool HttpRequest::timeout() const {
  return reply && reply->error() == QNetworkReply::OperationCanceledError;
}

void HttpRequest::sendRequest(const QString &requestURL, const HttpRequest::Method method) {
  if (active()) {
    qDebug() << "HttpRequest is active";
    return;
  }
  QString token;
  if(create_jwt) {
    token = CommaApi::create_jwt();
  } else {
    QString token_json = QString::fromStdString(util::read_file(util::getenv("HOME") + "/.comma/auth.json"));
    QJsonDocument json_d = QJsonDocument::fromJson(token_json.toUtf8());
    token = json_d["access_token"].toString();
  }

  QNetworkRequest request;
  request.setUrl(QUrl(requestURL));
  request.setRawHeader("User-Agent", getUserAgent().toUtf8());

  if (!token.isEmpty()) {
    request.setRawHeader(QByteArray("Authorization"), ("JWT " + token).toUtf8());
  }

  if (method == HttpRequest::Method::GET) {
    reply = nam()->get(request);
  } else if (method == HttpRequest::Method::DELETE) {
    reply = nam()->deleteResource(request);
  }

  networkTimer->start();
  connect(reply, &QNetworkReply::finished, this, &HttpRequest::requestFinished);
}

void HttpRequest::requestTimeout() {
  reply->abort();
}

void HttpRequest::requestFinished() {
  networkTimer->stop();

  if (reply->error() == QNetworkReply::NoError) {
    emit requestDone(reply->readAll(), true, reply->error());
  } else {
    QString error;
    if (reply->error() == QNetworkReply::OperationCanceledError) {
      nam()->clearAccessCache();
      nam()->clearConnectionCache();
      error = "Request timed out";
    } else {
      error = reply->errorString();
    }
    emit requestDone(error, false, reply->error());
  }

  reply->deleteLater();
  reply = nullptr;
}

QNetworkAccessManager *HttpRequest::nam() {
  static QNetworkAccessManager *networkAccessManager = new QNetworkAccessManager(qApp);
  return networkAccessManager;
}
