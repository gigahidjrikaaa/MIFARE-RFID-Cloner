#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN 10
#define RST_PIN 5

MFRC522 mfrc522(SS_PIN, RST_PIN);

#define BTN_READ_PIN 2
#define BTN_COPY_PIN 3
#define BUZZER_PIN 4
#define BTN_WRITE_PIN 6

bool dataCopied = false;
byte copiedData[16];

void setup() {
  Serial.begin(9600);
  SPI.begin();
  mfrc522.PCD_Init();

  pinMode(BTN_READ_PIN, INPUT_PULLUP);
  pinMode(BTN_COPY_PIN, INPUT_PULLUP);
  pinMode(BTN_WRITE_PIN, INPUT_PULLUP);
  pinMode(BUZZER_PIN, OUTPUT);

  Serial.println("Ready.");
}

void loop() {
  if (digitalRead(BTN_READ_PIN) == LOW) {
    tone(BUZZER_PIN, 500, 100);
    readRFID();
  }

  if (digitalRead(BTN_COPY_PIN) == LOW) {
    tone(BUZZER_PIN, 1500, 100);
    copyRFIDData();
    mfrc522.PCD_Init();
  }

  if (digitalRead(BTN_WRITE_PIN) == LOW && dataCopied) {
    tone(BUZZER_PIN, 750, 100);
    writeCopiedData();
    mfrc522.PCD_Init();
  }
}

void readRFID() {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  Serial.print("Card UID: ");
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.println();

  // No need to halt communication, just delay before the next operation
  delay(1000);
}

void copyRFIDData() {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  byte blockAddr = 1;
  MFRC522::StatusCode status;
  MFRC522::PICC_Type piccType;

  piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI &&
      piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
      piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
    Serial.println("This card is not supported for copying data.");
    return;
  }

  // This is a sample MIFARE Classic key (6 bytes) used for authentication.
  byte key[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  MFRC522::MIFARE_Key mifareKey;
  for (byte i = 0; i < 6; i++) {
    mifareKey.keyByte[i] = key[i];
  }

  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockAddr, &mifareKey, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.println("Authentication failed for the source card.");
    return;
  }

  Serial.println("Dumping card content:");
  byte buffer[18];
  byte bufferSize = sizeof(buffer);
  for (byte i = 0; i < 64; i++) {
    blockAddr = i;
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockAddr, &mifareKey, &(mfrc522.uid));
    if (status == MFRC522::STATUS_OK) {
      status = mfrc522.MIFARE_Read(blockAddr, buffer, &bufferSize);
      if (status == MFRC522::STATUS_OK) {
        Serial.print("Block ");
        Serial.print(blockAddr);
        Serial.print(": ");
        for (byte j = 0; j < 16; j++) {
          Serial.print(buffer[j] < 0x10 ? " 0" : " ");
          Serial.print(buffer[j], HEX);
        }
        Serial.println();
      } else {
        Serial.println("Reading data from the source card failed.");
        return;
      }
    }
  }

  dataCopied = true;
  Serial.println("Data copied successfully!");
  tone(BUZZER_PIN, 1000, 100);
  delay(200);
  tone(BUZZER_PIN, 1000, 100);
  delay(500);
}

//! TODO: Fix this function
void writeCopiedData() {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  MFRC522::StatusCode status;
  MFRC522::PICC_Type piccType;

  piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI &&
      piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
      piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
    Serial.println("This card is not supported for writing data.");
    return;
  }

  // This is a sample MIFARE Classic key (6 bytes) used for authentication.
  byte key[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  MFRC522::MIFARE_Key mifareKey;
  for (byte i = 0; i < 6; i++) {
    mifareKey.keyByte[i] = key[i];
  }

  byte blockAddr;
  byte bufferSize = sizeof(copiedData);

  // Authenticate with the target card using the same key as before
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 1, &mifareKey, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.println("Authentication failed for the target card.");
    return;
  }

  // Write the copied data to the target card
  for (byte i = 0; i < 64; i++) {
    blockAddr = i;
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockAddr, &mifareKey, &(mfrc522.uid));
    if (status == MFRC522::STATUS_OK) {
      status = mfrc522.MIFARE_Write(blockAddr, copiedData, bufferSize);
      if (status != MFRC522::STATUS_OK) {
        Serial.print("Block ");
        Serial.print(blockAddr);
        Serial.print(": Writing data to the target card failed. Status code: 0x");
        Serial.println(status, HEX);
        return;
      }
      // Small delay between writes to ensure reliable communication
      delay(100);
    } else {
      Serial.print("Block ");
      Serial.print(blockAddr);
      Serial.println(": Authentication failed for the target card.");
      return;
    }
  }

  Serial.println("Data written to the target card successfully!");
  tone(BUZZER_PIN, 1000, 100);
  delay(200);
  tone(BUZZER_PIN, 1000, 100);
  delay(500);
}
