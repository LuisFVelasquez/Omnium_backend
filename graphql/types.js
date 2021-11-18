import { gql } from 'apollo-server-express';
import { typesEnums } from '../models/enums/typesEnums.js';
import { tiposUsuario } from '../models/user/typesUser.js';

const typesGlobales = gql`
  scalar Date
`;

export const types = [ typesGlobales, typesEnums, tiposUsuario ];
