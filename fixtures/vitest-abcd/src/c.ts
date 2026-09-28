export const loadImpl = async (name: string) => import(`./impl-${name}.ts`);
