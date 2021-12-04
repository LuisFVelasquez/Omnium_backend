import { gql } from 'apollo-server-express';

const typesUser = gql`
  type Usuario {
    _id: ID!
    nombre: String!
    apellido: String!
    identificacion: String!
    correo: String!
    password: String!
    rol: Enum_Rol!
    estado: Enum_EstadoUsuario
  }
  type Perfil {
    _id: ID!
    nombre: String!
    apellido: String!
    identificacion: String!
    correo: String!
    rol: Enum_Rol!
  }
  type Query {
    Usuarios: [Usuario]
    Usuario(_id: String!): Usuario
    Perfil(_id: String!): Perfil
  }
  type Mutation {
    crearUsuario(
      nombre: String!
      apellido: String!
      identificacion: String!
      correo: String!
      rol: Enum_Rol!
      estado: Enum_EstadoUsuario
      password: String!
    ): Usuario

    editarUsuario(
      _id: String!
      nombre: String!
      apellido: String!
      identificacion: String!
      correo: String!
      estado: Enum_EstadoUsuario!
    ): Usuario

    eliminarUsuario(_id: String, correo: String): Usuario
  }
`;

export { typesUser };
