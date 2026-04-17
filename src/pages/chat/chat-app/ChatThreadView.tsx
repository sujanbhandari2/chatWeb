import type { LegacyRef } from 'react';
import { useChatStore } from '../../../store/useChatStore';
import { toAbsoluteMediaUrl } from '../../../utils/media.utils';
import {
  getMessageType,
  isGlobalConversation,
  isGroupConversation,
  summarizeReactions,
  userDisplayName,
  userInitials
} from '../../../utils/chat.utils';
import {
  QUICK_REACTION_EMOJIS,
  TRANSLATE_TARGET_LANGS,
  translateLangLabel
} from '../../../features/chat/chat.constants';
import {
  AvatarWithPresence,
  IconAttach,
  IconCheckSend,
  IconImage,
  IconRecord,
  IconSend,
  formatRecordingDuration,
  getDeliveryStatus
} from '../../../features/chat/chat-ui';
import { useChatThreadState } from '../../../hooks/useChatThreadState';

/** Active conversation: header, message list, composer, and recording bar. */
export function ChatThreadView(): JSX.Element {
  const {
    features,
    user,
    selectedConversationId,
    widgetRailPane,
    messages,
    text,
    setText,
    error,
    chatHeaderMenuOpen,
    setChatHeaderMenuOpen,
    messageActionsMenuId,
    setMessageActionsMenuId,
    messageSpeechUi,
    patchMessageSpeechUi,
    widgetBackToInbox,
    openEditGroupModal,
    handleDeleteSelectedConversation,
    deletingConversation,
    handleSendText,
    handleReact,
    handleMarkRead,
    handleDelete,
    handleTranscribeVoiceMessage,
    handleTranslateForMessage,
    isRecording,
    recordingDurationMs,
    selectedConversation,
    selectedDirectPeerId,
    getConversationTitle,
    getConversationSubtitle,
    isPeerOnline,
    messageScrollerRef,
    chatHeaderMenuRef,
    startRecording,
    finishRecording,
    cancelRecording,
    usersById,
  } = useChatThreadState();

  if (!user) {
    return <div className="blank-chat">Sign in to chat.</div>;
  }

  const getSenderLabel = (senderId: string): string => {
    if (senderId === user.id) {
      return 'You';
    }
    const tenantUser = usersById.get(senderId);
    if (tenantUser) {
      return userDisplayName(tenantUser);
    }
    return senderId.slice(0, 8);
  };

  return (
    <main
      className="chat-stage chat-stage--widget"
      aria-hidden={!selectedConversationId || widgetRailPane !== 'chats'}
    >
      {!selectedConversation ? (
        <div className="blank-chat">Pick a chat from the list or search above.</div>
      ) : (
        <>
          <header className="chat-header">
            <div className="chat-header-main">
              <button
                type="button"
                className="chat-header-back"
                onClick={widgetBackToInbox}
                aria-label="Back to chat list"
              >
                ←
              </button>
              {selectedDirectPeerId !== undefined ? (
                <AvatarWithPresence online={isPeerOnline(selectedDirectPeerId)}>
                  <div className="avatar-pill">
                    {isGlobalConversation(selectedConversation)
                      ? 'ALL'
                      : userInitials(selectedConversation.participants[0]?.user ?? { name: null, email: '?' })}
                  </div>
                </AvatarWithPresence>
              ) : (
                <div className="avatar-pill">
                  {isGlobalConversation(selectedConversation)
                    ? 'ALL'
                    : userInitials(selectedConversation.participants[0]?.user ?? { name: null, email: '?' })}
                </div>
              )}
              <div className="chat-header-titles">
                <h3>{getConversationTitle(selectedConversation)}</h3>
                <p>{getConversationSubtitle(selectedConversation)}</p>
              </div>
            </div>
            <div className="chat-header-menu-wrap" ref={chatHeaderMenuRef as LegacyRef<HTMLDivElement>}>
              <button
                type="button"
                className="chat-header-menu-btn"
                aria-expanded={chatHeaderMenuOpen}
                aria-haspopup="menu"
                aria-label="Chat options"
                onClick={() => setChatHeaderMenuOpen((open) => !open)}
              >
                ⋮
              </button>
              {chatHeaderMenuOpen && (
                <div className="rail-menu-dropdown chat-header-dropdown" role="menu">
                  {features.editGroup && isGroupConversation(selectedConversation) && (
                    <button type="button" role="menuitem" className="rail-menu-item" onClick={() => openEditGroupModal()}>
                      Edit group
                    </button>
                  )}
                  {features.deleteConversation && !isGlobalConversation(selectedConversation) && (
                    <button
                      type="button"
                      role="menuitem"
                      className="rail-menu-item rail-menu-item-danger"
                      disabled={deletingConversation}
                      onClick={() => void handleDeleteSelectedConversation()}
                    >
                      {deletingConversation ? 'Deleting…' : 'Delete Chat'}
                    </button>
                  )}
                </div>
              )}
            </div>
          </header>

          <section className="message-scroller" ref={messageScrollerRef as LegacyRef<HTMLElement>}>
            {messages.map((message) => {
              const isMine = message.senderId === user.id;
              const status = isMine ? getDeliveryStatus(message) : null;
              const showSenderLabel =
                selectedConversation != null &&
                (isGroupConversation(selectedConversation) || isGlobalConversation(selectedConversation));
              const menuOpen = messageActionsMenuId === message.id;
              const speechUi = messageSpeechUi[message.id];

              return (
                <div key={message.id} className={`message-row-outer ${isMine ? 'mine' : 'theirs'}`}>
                  <div
                    className={`message-cluster ${isMine ? 'mine' : 'theirs'}${menuOpen ? ' message-cluster--menu-open' : ''}`}
                  >
                    <div className="message-content-stack">
                      {!message.deletedAt && (
                        <div className="message-hover-actions">
                          {features.messageReactions && (
                            <div className="message-reaction-strip" role="toolbar" aria-label="Quick reactions">
                              {QUICK_REACTION_EMOJIS.map((emoji) => (
                                <button
                                  key={emoji}
                                  type="button"
                                  className="message-reaction-strip-btn"
                                  aria-label={`React ${emoji}`}
                                  onClick={() => handleReact(message.id, emoji)}
                                >
                                  {emoji}
                                </button>
                              ))}
                            </div>
                          )}
                          <div className="message-more-wrap" data-message-menu-root={message.id}>
                            <button
                              type="button"
                              className="message-more-btn"
                              aria-expanded={menuOpen}
                              aria-haspopup="menu"
                              aria-label="Message actions"
                              onClick={(event) => {
                                event.stopPropagation();
                                setMessageActionsMenuId((current) => (current === message.id ? null : message.id));
                              }}
                            >
                              ⋮
                            </button>
                            {menuOpen && (
                              <div className="message-actions-dropdown" role="menu">
                                {features.messageReactions && (
                                  <div className="message-actions-reactions" role="none">
                                    <span className="message-actions-reactions-label">React</span>
                                    <div className="message-actions-reactions-row" role="group">
                                      {QUICK_REACTION_EMOJIS.map((emoji) => (
                                        <button
                                          key={emoji}
                                          type="button"
                                          role="menuitem"
                                          className="message-actions-emoji-btn"
                                          aria-label={`React ${emoji}`}
                                          onClick={() => handleReact(message.id, emoji)}
                                        >
                                          {emoji}
                                        </button>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {!isMine && (
                                  <button
                                    type="button"
                                    role="menuitem"
                                    className="message-actions-item"
                                    onClick={() => {
                                      setMessageActionsMenuId(null);
                                      void handleMarkRead(message.id);
                                    }}
                                  >
                                    Mark as read
                                  </button>
                                )}
                                {isMine && (
                                  <button
                                    type="button"
                                    role="menuitem"
                                    className="message-actions-item message-actions-item-danger"
                                    onClick={() => {
                                      setMessageActionsMenuId(null);
                                      void handleDelete(message.id);
                                    }}
                                  >
                                    Delete
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      <article className={`message-bubble ${isMine ? 'mine' : 'theirs'}`}>
                        {showSenderLabel && (
                          <div className="message-label">{getSenderLabel(message.senderId)}</div>
                        )}
                        {message.deletedAt ? (
                          <em className="deleted">Message deleted</em>
                        ) : getMessageType(message) === 'IMAGE' ? (
                          <img src={toAbsoluteMediaUrl(message.content)} alt="Uploaded" />
                        ) : getMessageType(message) === 'VOICE' ? (
                          <>
                            <audio controls src={toAbsoluteMediaUrl(message.content)} />
                            {(features.voiceTranscription || features.translateMessages) && (
                              <div className="message-msgr-translation">
                                {!speechUi?.transcript ? (
                                  features.voiceTranscription ? (
                                    <>
                                      <button
                                        type="button"
                                        className="message-msgr-link"
                                        disabled={speechUi?.loading === 'transcribe'}
                                        onClick={() => void handleTranscribeVoiceMessage(message)}
                                      >
                                        {speechUi?.loading === 'transcribe' ? 'Transcribing…' : 'Transcribe'}
                                      </button>
                                      {speechUi?.error && !speechUi?.transcript ? (
                                        <p className="message-msgr-error" role="alert">
                                          {speechUi.error}
                                        </p>
                                      ) : null}
                                    </>
                                  ) : null
                                ) : (
                                  <>
                                    <p className="message-msgr-transcript">{speechUi.transcript}</p>
                                    {features.translateMessages &&
                                      (speechUi.translated ? (
                                        <>
                                          <div className="message-msgr-divider" aria-hidden />
                                          <p className="message-msgr-meta">
                                            Translation · {translateLangLabel(speechUi.targetLang ?? 'en')}
                                          </p>
                                          <p className="message-msgr-translation-body" aria-live="polite">
                                            {speechUi.translated}
                                          </p>
                                          <button
                                            type="button"
                                            className="message-msgr-link"
                                            onClick={() =>
                                              patchMessageSpeechUi(message.id, {
                                                translated: undefined,
                                                error: undefined,
                                                translateToolsOpen: false
                                              })
                                            }
                                          >
                                            See original
                                          </button>
                                        </>
                                      ) : speechUi.translateToolsOpen ? (
                                        <div className="message-msgr-tools">
                                          <label className="visually-hidden" htmlFor={`trg-voice-${message.id}`}>
                                            Language
                                          </label>
                                          <select
                                            id={`trg-voice-${message.id}`}
                                            className="message-msgr-select"
                                            value={speechUi.targetLang ?? 'en'}
                                            onChange={(event) =>
                                              patchMessageSpeechUi(message.id, { targetLang: event.target.value })
                                            }
                                          >
                                            {TRANSLATE_TARGET_LANGS.map((lang) => (
                                              <option key={lang.code} value={lang.code}>
                                                {lang.label}
                                              </option>
                                            ))}
                                          </select>
                                          <button
                                            type="button"
                                            className="message-msgr-link"
                                            disabled={speechUi.loading === 'translate'}
                                            onClick={() =>
                                              void handleTranslateForMessage(
                                                message,
                                                speechUi.transcript ?? '',
                                                speechUi.targetLang ?? 'en'
                                              )
                                            }
                                          >
                                            {speechUi.loading === 'translate' ? 'Translating…' : 'See translation'}
                                          </button>
                                        </div>
                                      ) : (
                                        <button
                                          type="button"
                                          className="message-msgr-link"
                                          onClick={() =>
                                            patchMessageSpeechUi(message.id, { translateToolsOpen: true })
                                          }
                                        >
                                          See translation
                                        </button>
                                      ))}
                                    {speechUi.error && speechUi.transcript && !speechUi.translated ? (
                                      <p className="message-msgr-error" role="alert">
                                        {speechUi.error}
                                      </p>
                                    ) : null}
                                  </>
                                )}
                              </div>
                            )}
                          </>
                        ) : (
                          <>
                            <p>{message.content}</p>
                            {features.translateMessages && (
                              <div className="message-msgr-translation">
                                {speechUi?.translated ? (
                                  <>
                                    <div className="message-msgr-divider" aria-hidden />
                                    <p className="message-msgr-meta">
                                      Translation · {translateLangLabel(speechUi?.targetLang ?? 'en')}
                                    </p>
                                    <p className="message-msgr-translation-body" aria-live="polite">
                                      {speechUi.translated}
                                    </p>
                                    <button
                                      type="button"
                                      className="message-msgr-link"
                                      onClick={() =>
                                        patchMessageSpeechUi(message.id, {
                                          translated: undefined,
                                          error: undefined,
                                          translateToolsOpen: false
                                        })
                                      }
                                    >
                                      See original
                                    </button>
                                  </>
                                ) : speechUi?.translateToolsOpen ? (
                                  <>
                                    <div className="message-msgr-tools">
                                      <label className="visually-hidden" htmlFor={`trg-text-${message.id}`}>
                                        Language
                                      </label>
                                      <select
                                        id={`trg-text-${message.id}`}
                                        className="message-msgr-select"
                                        value={speechUi?.targetLang ?? 'en'}
                                        onChange={(event) =>
                                          patchMessageSpeechUi(message.id, { targetLang: event.target.value })
                                        }
                                      >
                                        {TRANSLATE_TARGET_LANGS.map((lang) => (
                                          <option key={lang.code} value={lang.code}>
                                            {lang.label}
                                          </option>
                                        ))}
                                      </select>
                                      <button
                                        type="button"
                                        className="message-msgr-link"
                                        disabled={speechUi?.loading === 'translate'}
                                        onClick={() =>
                                          void handleTranslateForMessage(
                                            message,
                                            message.content,
                                            speechUi?.targetLang ?? 'en'
                                          )
                                        }
                                      >
                                        {speechUi?.loading === 'translate' ? 'Translating…' : 'See translation'}
                                      </button>
                                    </div>
                                    {speechUi?.error ? (
                                      <p className="message-msgr-error" role="alert">
                                        {speechUi.error}
                                      </p>
                                    ) : null}
                                  </>
                                ) : (
                                  <button
                                    type="button"
                                    className="message-msgr-link"
                                    onClick={() => patchMessageSpeechUi(message.id, { translateToolsOpen: true })}
                                  >
                                    See translation
                                  </button>
                                )}
                              </div>
                            )}
                          </>
                        )}

                        <div className="message-info">
                          <span>{new Date(message.createdAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</span>
                          {status && (
                            <span className={`message-status ${status}`} aria-label={`Message ${status}`}>
                              {status === 'sent' ? '✓' : '✓✓'}
                            </span>
                          )}
                        </div>
                      </article>

                      {!message.deletedAt && (message.reactions ?? []).length > 0 && (
                        <div className="message-reactions message-reactions-below" aria-label="Reactions">
                          {summarizeReactions(message.reactions ?? [], user.id).map((group) => (
                            <span
                              key={group.emoji}
                              className={`message-reaction-chip ${group.mine ? 'message-reaction-chip--mine' : ''}`}
                              title={group.title}
                            >
                              <span className="message-reaction-emoji">{group.emoji}</span>
                              {group.count > 1 && <span className="message-reaction-count">{group.count}</span>}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </section>

          {isRecording ? (
            <footer className="recording-bar" role="status" aria-live="polite">
              <button type="button" className="recording-bar-cancel" onClick={cancelRecording}>
                Cancel
              </button>
              <div className="recording-bar-center">
                <span className="recording-bar-dot" aria-hidden />
                <div className="recording-bars" aria-hidden>
                  <span />
                  <span />
                  <span />
                  <span />
                  <span />
                </div>
                <div className="recording-bar-text">
                  <span className="recording-bar-title">Recording</span>
                  <span className="recording-bar-time">{formatRecordingDuration(recordingDurationMs)}</span>
                </div>
              </div>
              <button
                type="button"
                className="recording-bar-done"
                title="Send voice message"
                aria-label="Send voice message"
                onClick={finishRecording}
              >
                <IconCheckSend />
                <span className="recording-bar-done-label">Send</span>
              </button>
            </footer>
          ) : (
            <footer className="composer-bar">
              <input
                className="composer-input"
                value={text}
                onChange={(event) => setText(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && !event.shiftKey) {
                    event.preventDefault();
                    void handleSendText();
                  }
                }}
                placeholder="Type a message… (Enter to send)"
                aria-label="Message text"
              />
              <div
                className="composer-actions"
                role="group"
                aria-label={
                  features.imageUpload || features.audioAttachmentUpload || features.voiceRecording
                    ? 'Attachments and send'
                    : 'Send message'
                }
              >
                {features.imageUpload && (
                  <label className="composer-icon-btn" title="Attach image">
                    <IconImage />
                    <span className="visually-hidden">Attach image</span>
                    <input
                      type="file"
                      accept="image/*"
                      onChange={(event) => {
                        const file = event.target.files?.[0];
                        if (file) {
                          void useChatStore.getState().handleSendUploadedMessage(file, 'IMAGE');
                        }
                        event.target.value = '';
                      }}
                    />
                  </label>
                )}
                {features.audioAttachmentUpload && (
                  <label className="composer-icon-btn" title="Attach audio file">
                    <IconAttach />
                    <span className="visually-hidden">Attach audio file</span>
                    <input
                      type="file"
                      accept="audio/*"
                      onChange={(event) => {
                        const file = event.target.files?.[0];
                        if (file) {
                          void useChatStore.getState().handleSendUploadedMessage(file, 'VOICE');
                        }
                        event.target.value = '';
                      }}
                    />
                  </label>
                )}
                {features.voiceRecording && (
                  <button
                    type="button"
                    className="composer-icon-btn composer-record-btn"
                    title="Record voice message"
                    aria-label="Record voice message"
                    onClick={() => void startRecording()}
                  >
                    <IconRecord />
                  </button>
                )}
                <button
                  type="button"
                  className="composer-icon-btn composer-send-btn"
                  title="Send"
                  aria-label="Send message"
                  disabled={!text.trim()}
                  onClick={() => void handleSendText()}
                >
                  <IconSend />
                </button>
              </div>
            </footer>
          )}
        </>
      )}

      {error && <p className="error-banner inline">{error}</p>}
    </main>
  );
}
