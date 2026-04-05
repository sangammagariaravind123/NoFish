export async function getLocal(keys) {
  return chrome.storage.local.get(keys);
}

export async function setLocal(values) {
  await chrome.storage.local.set(values);
}

export async function removeLocal(keys) {
  await chrome.storage.local.remove(keys);
}

export async function getValue(key, fallbackValue = null) {
  const result = await getLocal([key]);
  return result[key] ?? fallbackValue;
}

export async function setValue(key, value) {
  await setLocal({ [key]: value });
}

export async function updateValue(key, updater, fallbackValue) {
  const currentValue = await getValue(key, fallbackValue);
  const nextValue = await updater(currentValue);
  await setValue(key, nextValue);
  return nextValue;
}
