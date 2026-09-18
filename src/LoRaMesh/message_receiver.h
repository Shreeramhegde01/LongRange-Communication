/*==============================================================================
  message_receiver.h
  ------------------------------------------------------------------------------
  Lógica de recepción y filtrado de mensajes.
  – Verifica duplicados, ACK pendientes y ventana de colisión.
  – Expone processReceivedMessage(), addMessageID(), isPendingAck(), etc.
==============================================================================*/
#ifndef MESSAGE_RECEIVER_H
#define MESSAGE_RECEIVER_H

#include "config.h"
#include "packet_manager.h"
#include "communication_manager.h"

/*----------------------------------------------------------------------------*/
/*  Declaración adelantada (planificador)                                     */
/*----------------------------------------------------------------------------*/
void increaseWaitTime(); //message_schedualer.h

/*----------------------------------------------------------------------------*/
/*  Historial de messageID (detección de duplicados)                          */
/*----------------------------------------------------------------------------*/
static uint32_t messageIDHistory[MAX_DUPLICATE_HISTORY];
static int idHistoryIndex = 0;

/*----------------------------------------------------------------------------*/
/*  Gestión del historial                                                     */
/*----------------------------------------------------------------------------*/
inline void addMessageID(uint32_t messageID) {
    messageIDHistory[idHistoryIndex] = messageID;
    idHistoryIndex++;
    if(idHistoryIndex >= MAX_DUPLICATE_HISTORY) {
        idHistoryIndex = 0;
    }
}

inline bool checkDuplicates(uint32_t messageID) {
    for(int i=0; i<MAX_DUPLICATE_HISTORY; i++) {
        if(messageIDHistory[i] == messageID) {
            return true; 
        }
    }
    return false;
}

inline void addMessageIDAfterAck(uint32_t messageID) {
    for(int i = 0; i < MAX_DUPLICATE_HISTORY; i++){
        if(messageIDHistory[i] == messageID){
            return;
        }
    }
    addMessageID(messageID);
    Serial.printf("[addMessageIDAfterAck] Se añade messageID=%u al historial de duplicados.\n", messageID);
}

/*----------------------------------------------------------------------------*/
/*  Consulta de ACK pendientes                                                */
/*----------------------------------------------------------------------------*/
inline bool isPendingAck(uint32_t messageID) {
    for (int i = 0; i < MAX_PENDING_ACKS; i++) {
        if (pendingAcks[i].timestamp != 0 &&
            pendingAcks[i].packet.messageID == messageID) {
            return true;    
        }
    }
    return false;
}

/*----------------------------------------------------------------------------*/
/*  Inicialización (vacía, pero se deja por simetría)                         */
/*----------------------------------------------------------------------------*/
inline void initMessageReceiver() {
}

/*============================================================================*/
/*  processReceivedMessage(): procesa si receptionDone == true                */
/*============================================================================*/
inline uint8_t processReceivedMessage(unsigned long &oledDisplayTime) {
    if (receptionDone) {
        uint8_t receivedType = receivedBuffer[0]; 
        processPayload();
        receptionDone = false;
        increaseWaitTime(); // aleatoriza back-off
        oledDisplayTime = millis();
        return receivedType;
    }
    return 0;
}

/*============================================================================*/
/*  Ventana de escucha (LBT)                                                  */
/*============================================================================*/
/*  Listen-before-talk using the transceiver's channel activity detector.
 *
 *  The base project listened for a fixed 500 ms window before every frame.
 *  CAD answers the same question in about 5 ms, which is what makes a
 *  multi-hop delivery fit inside the latency budget.                       */
inline void windowCollisionPrevention() {
  for (int attempt = 1; attempt <= MAX_WINDOW_RETRIES; attempt++) {
    /* The main loop is blocked here, so radio interrupts must be drained
     * locally or a frame arriving mid-backoff would be missed. */
    processRadioEvents();
    if (receptionDone) {
      unsigned long packetTime = 0;
      processReceivedMessage(packetTime);
    }

    if (!loraAntena.channelBusy()) {
      return; // clear to transmit
    }
    delay(random(BACKOFF_LOWER, BACKOFF_UPPER));
  }
  Serial.printf("[LBT] channel busy after %d attempts - transmitting anyway\n",
                MAX_WINDOW_RETRIES);
}

#endif
