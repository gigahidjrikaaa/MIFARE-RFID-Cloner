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

// Adjust the size of the copiedData array to hold data from all blocks of a MIFARE Classic 4K card
byte copiedData[1024];

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

  // Output the type of the card
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.print("Card Type: ");
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
  successTone();

  // No need to halt communication, just delay before the next operation
  delay(300);
}

void errorTone()
{
  tone(BUZZER_PIN, 150, 100);
  delay(200);
  tone(BUZZER_PIN, 150, 100);
  delay(700);
}

void successTone()
{
  tone(BUZZER_PIN, 1000, 100);
  delay(200);
  tone(BUZZER_PIN, 1000, 100);
  delay(500);
}

bool isSectorTrailer(byte blockAddr) {
  return ((blockAddr + 1) % 4 == 0) || (blockAddr == 127); // For MIFARE Classic 1K and Mini
}

void copyRFIDData() {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  MFRC522::StatusCode status;
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  byte maxBlocks = 0;

  switch (piccType) {
    case MFRC522::PICC_TYPE_MIFARE_MINI:
      maxBlocks = 20;
      break;
    case MFRC522::PICC_TYPE_MIFARE_1K:
      maxBlocks = 64;
      break;
    case MFRC522::PICC_TYPE_MIFARE_4K:
      maxBlocks = 256;
      break;
    default:
      Serial.println("This card is not supported for copying data.");
      errorTone();
      return;
  }

  byte key[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  MFRC522::MIFARE_Key mifareKey;
  for (byte i = 0; i < 6; i++) {
    mifareKey.keyByte[i] = key[i];
  }

  byte buffer[18];
  byte bufferSize = sizeof(buffer);

  for (byte blockAddr = 0; blockAddr < maxBlocks; blockAddr++) {
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockAddr, &mifareKey, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
      Serial.println("Authentication failed for the source card.");
      errorTone();
      return;
    }

    status = mfrc522.MIFARE_Read(blockAddr, buffer, &bufferSize);
    if (status == MFRC522::STATUS_OK) {
      tone(BUZZER_PIN, 200 + blockAddr * 25, 25);
      // Output the data inside of the card
      Serial.print("Block ");
      Serial.print(blockAddr);
      if (isSectorTrailer(blockAddr)) {
        Serial.print(" [SECTOR TRAILER]: ");
      } else {
        Serial.print(": ");
      }
      for (byte j = 0; j < 16; j++) {
        Serial.print(buffer[j] < 0x10 ? " 0" : " ");
        Serial.print(buffer[j], HEX);
        copiedData[blockAddr * 16 + j] = buffer[j];
      }
      Serial.println();
    } else {
      Serial.println("Reading data from the source card failed.");
      errorTone();
      return;
    }
  }

  dataCopied = true;
  Serial.println("Data copied successfully!");
  successTone();
}

void writeCopiedData() {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  MFRC522::StatusCode status;
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  byte maxBlocks = 0;

  switch (piccType) {
    case MFRC522::PICC_TYPE_MIFARE_MINI:
      maxBlocks = 20;
      break;
    case MFRC522::PICC_TYPE_MIFARE_1K:
      maxBlocks = 64;
      break;
    case MFRC522::PICC_TYPE_MIFARE_4K:
      maxBlocks = 256;
      break;
    default:
      Serial.println("This card is not supported for writing data.");
      errorTone();
      return;
  }

  byte key[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  MFRC522::MIFARE_Key mifareKey;
  for (byte i = 0; i < 6; i++) {
    mifareKey.keyByte[i] = key[i];
  }

  for (byte blockAddr = 0; blockAddr < maxBlocks; blockAddr++) {
    // if (blockAddr == 0) continue; // Skip writing to Block 0 (Manufacturer Block)
    if (isSectorTrailer(blockAddr)) continue; // Skip writing to sector trailers

    tone(BUZZER_PIN, 200 + blockAddr * 25, 25);
    Serial.print("Writing to Block ");
    Serial.print(blockAddr);
    Serial.print("... ");

    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockAddr, &mifareKey, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
      Serial.println("Authentication failed for the target card.");
      errorTone();
      return;
    }

    status = mfrc522.MIFARE_Write(blockAddr, &copiedData[blockAddr * 16], 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print("Failed! Status code: 0x");
      Serial.println(status, HEX);
      errorTone();
      return;
    } else {
      Serial.println("Success!");
    }
  }

  Serial.println("Data written to the target card successfully!");
  successTone();
}